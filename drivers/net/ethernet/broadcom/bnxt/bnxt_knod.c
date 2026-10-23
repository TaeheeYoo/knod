// SPDX-License-Identifier: GPL-2.0-only
/*
 * knod: XDP programs offloaded to an accel, which runs the device's queues
 * through devmem queue ownership (bnxt_dmq.c).  Here are what knod needs of
 * the driver besides: attach and detach, the offloaded program and maps, and
 * the queue's NAPI, which knod kicks to hand packets the accel passed to the
 * stack.
 */

#include <linux/pci.h>
#include <net/knod.h>
#include <net/netdev_lock.h>
#include <linux/bnxt/hsi.h>

#include "bnxt.h"
#include "bnxt_knod.h"

/* Where queue @i's interrupt is set to run, which no interrupt of the accel's
 * rings comes to: knod kicks the queue's NAPI there to hand packets the accel
 * passed to the stack.
 */
void bnxt_knod_irq_moved(struct bnxt *bp, int i, const struct cpumask *mask)
{
	struct knod_dev *knodev = READ_ONCE(bp->knodev);
	unsigned int cpu;

	if (!knodev || i >= KNOD_SPSC_MAX || i >= bp->rx_nr_rings)
		return;
	cpu = cpumask_first_and(mask, cpu_online_mask);
	WRITE_ONCE(knodev->wpriv[i].napi_cpu, cpu < nr_cpu_ids ? cpu : -1);
}

/* The NIC is up: knod onto it. */
void bnxt_knod_open(struct bnxt *bp)
{
	struct knod_dev *knodev = bp->knodev;
	int i;

	if (!knodev)
		return;

	for (i = 0; i < bp->rx_nr_rings && i < KNOD_SPSC_MAX; i++) {
		WRITE_ONCE(knodev->wpriv[i].napi_cpu, -1);
		if (bp->ring_cpu_mask)
			bnxt_knod_irq_moved(bp, i, bp->ring_cpu_mask[i]);
		WRITE_ONCE(knodev->wpriv[i].napi, &bp->bnapi[i]->napi);
	}
	knod_dev_start(knodev);
}

/* Before the rings go: knod off them, and the copies to the stack that still
 * hold RX pages landed, while the page pools are still there.
 */
void bnxt_knod_close(struct bnxt *bp)
{
	struct knod_dev *knodev = bp->knodev;
	int i;

	if (!knodev)
		return;

	knod_dev_stop(knodev);
	for (i = 0; i < KNOD_SPSC_MAX; i++)
		WRITE_ONCE(knodev->wpriv[i].napi, NULL);
	/* With wpriv[].napi cleared no poll runs the drain any more. */
	synchronize_net();
	knod_dev_flush_pass(knodev);
}

/* NAPI: what the accel passed to the stack, kicked here by knod. */
int bnxt_knod_drain(struct bnxt *bp, struct bnxt_napi *bnapi, int budget)
{
	struct knod_dev *knodev = READ_ONCE(bp->knodev);
	struct napi_struct *napi;

	if (!knodev || bnapi->index >= KNOD_SPSC_MAX)
		return 0;
	napi = READ_ONCE(knodev->wpriv[bnapi->index].napi);
	if (!napi)
		return 0;
	return knod_dev_xdp_drain_pass(knodev, napi, bnapi->index, budget);
}

static int bnxt_knod_attach(struct knod_dev *knodev)
{
	struct bnxt *bp = netdev_priv(knodev->netdev);
	struct net_device *dev = bp->dev;

	netdev_assert_locked(dev);
	if (!(bp->flags & BNXT_FLAG_CHIP_P5_PLUS)) {
		netdev_warn(dev, "knod offload runs only on P5 and P7 rings\n");
		return -EOPNOTSUPP;
	}
	if (bp->xdp_prog) {
		netdev_warn(dev, "knod offload does not run with an XDP program\n");
		return -EOPNOTSUPP;
	}
	if (bp->rx_nr_rings > KNOD_SPSC_MAX) {
		netdev_warn(dev, "knod offload supports up to %d channels\n",
			    KNOD_SPSC_MAX);
		return -EOPNOTSUPP;
	}
	WRITE_ONCE(bp->knodev, knodev);
	return 0;
}

static int bnxt_knod_detach(struct knod_dev *knodev)
{
	struct bnxt *bp = netdev_priv(knodev->netdev);

	WRITE_ONCE(bp->knodev, NULL);
	return 0;
}

static struct knod_nic_ops bnxt_knod_nic_ops = {
	.attach = bnxt_knod_attach,
	.detach = bnxt_knod_detach,
};

int bnxt_knod_xdp(struct bnxt *bp, struct netdev_bpf *xdp)
{
	if (!bp->knodev)
		return -EOPNOTSUPP;
	return knod_dev_xdp_install(bp->knodev, xdp);
}

int bnxt_knod_init(struct bnxt *bp)
{
	struct knod_netdev *knetdev;

	knetdev = kzalloc_obj(struct knod_netdev, GFP_KERNEL);
	if (!knetdev)
		return -ENOMEM;

	INIT_LIST_HEAD(&knetdev->list);
	knetdev->dev = bp->dev;
	knetdev->priv = bp;
	knetdev->nic_ops = &bnxt_knod_nic_ops;
	knetdev->owner = THIS_MODULE;
	knetdev->flags |= KNOD_FLAGS_XDP;
	knod_netdev_register(knetdev);
	bp->knetdev = knetdev;
	return 0;
}

void bnxt_knod_uninit(struct bnxt *bp)
{
	if (!bp->knetdev)
		return;
	knod_netdev_unregister(bp->knetdev);
	kfree(bp->knetdev);
	bp->knetdev = NULL;
}
