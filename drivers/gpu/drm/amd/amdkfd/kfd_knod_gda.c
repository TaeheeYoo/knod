// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * The KNOD GDA engine: a persistent shader, one workgroup per queue, that
 * runs a NIC's rings itself - polls its receive CQ, keeps its RQ posted,
 * sends XDP_TX on its XDP SQ and hands XDP_PASS to the host - with whatever
 * code is installed between the rings' prologue and epilogue.  With no
 * program that is the core blob's receive kernel, which passes everything;
 * the BPF feature installs its programs in its place.
 */
#include <linux/module.h>
#include <linux/log2.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/debugfs.h>
#include <linux/vmalloc.h>
#include <linux/seq_file.h>
#include <linux/netdevice.h>
#include <net/page_pool/helpers.h>
#include "kfd_priv.h"
#include "kfd_knod.h"
#include "knod_param.h"
#include "knod_persistent.h"
#include "hdp/hdp_5_0_0_offset.h"
#include "hdp/hdp_5_0_0_sh_mask.h"

/* Lanes in a queue's workgroup; a wave of them per 64, up to
 * KNOD_PERSIST_GDA_WAVES_MAX taking packets.
 */
static unsigned int knod_gda_workgroups = 256;
MODULE_PARM_DESC(knod_workgroups, "KNOD: lanes in each queue's persistent workgroup: 64, 128, 192 or 256");
module_param_named(knod_workgroups, knod_gda_workgroups, uint, 0444);

/* One packet a page, so there is always room to move a packet's start off the
 * offset every other one has; all at one offset put every packet on one
 * memory channel.  Which step spreads them best depends on the GPU's address
 * hash: 128 did best on Navi 21, where 64 and 256 both did worse; 256 is the
 * default.  Zero leaves them where they were.  Fixed at load: the RQ is
 * posted once per build of the rings.
 */
static unsigned int knod_gda_stagger = 256;
MODULE_PARM_DESC(knod_gda_stagger, "KNOD: bytes between the offsets packets start at, a power of two (0 = one offset)");
module_param_named(knod_gda_stagger, knod_gda_stagger, uint, 0444);

static void knod_gda_wake_worker(struct knod_gda *g)
{
	atomic_inc(&g->worker_events);
	wake_up(&g->pass_wq);
}

struct knod_persistent_mem {
	struct knod_persistent_control control;
	struct amd_signal terminal;
};

static_assert(KNOD_GDA_DB_OFF + KNOD_GDA_RQ_DB == KNOD_PERSIST_RING_RQ_DB);
static_assert(KNOD_GDA_DB_OFF + KNOD_GDA_CQ_DB == KNOD_PERSIST_RING_CQ_DB);
/* The send counter is the record's second; see MLX5_SND_DBR. */
static_assert(KNOD_GDA_DB_OFF + KNOD_GDA_SQ_DB + 4 == KNOD_PERSIST_RING_SQ_DB);
static_assert(KNOD_GDA_DB_OFF + KNOD_GDA_TX_CQ_DB == KNOD_PERSIST_RING_TX_CQ_DB);
static_assert(KNOD_PERSIST_RING_RQ_OFF == KNOD_GDA_RQ_OFF);
static_assert(KNOD_PERSIST_RING_CQ_OFF == KNOD_GDA_CQ_OFF);
static_assert(KNOD_PERSIST_RING_TX_CQ_OFF == KNOD_GDA_TX_CQ_OFF);
static_assert(KNOD_PERSIST_RING_RQPOS_OFF == KNOD_GDA_RQPOS_OFF);
static_assert(KNOD_GDA_RQPOS_BYTES / 4 == KNOD_GDA_SQ_BYTES / 64);
static_assert(KNOD_PERSIST_PASS_CSUM_OK == KNOD_PASS_CSUM_OK);
static_assert(KNOD_PERSIST_PASS_CSUM_INNER == KNOD_PASS_CSUM_INNER);
static_assert(KNOD_PERSIST_PASS_IPSEC_CSUM == KNOD_PASS_IPSEC_CSUM);
static_assert(KNOD_PERSIST_PASS_CC + 4 <= SMP_CACHE_BYTES);
/* The blob's engines are keyed by the NIC formats devmem gives. */
static_assert(NET_DMQ_FMT_NONE == KNOD_PERSIST_FMT_NONE);
static_assert(NET_DMQ_FMT_MLX5_CX5 == KNOD_PERSIST_FMT_MLX5_CX5);
static_assert(NET_DMQ_FMT_BNXT_P5 == KNOD_PERSIST_FMT_BNXT_P5);
static_assert(NET_DMQ_FMT_BNXT_P7 == KNOD_PERSIST_FMT_BNXT_P7);
static_assert(NET_DMQ_BNXT_RQ == KNOD_PERSIST_DB_RQ);
static_assert(NET_DMQ_BNXT_RX_CQ == KNOD_PERSIST_DB_RX_CQ);
static_assert(NET_DMQ_BNXT_SQ == KNOD_PERSIST_DB_SQ);
static_assert(NET_DMQ_BNXT_TX_CQ == KNOD_PERSIST_DB_TX_CQ);
static_assert(NET_DMQ_BNXT_RINGS == KNOD_PERSIST_DB_KEYS);

/* bnxt's: no doorbell records, every ring at one doorbell. */
static bool knod_gda_fmt_bnxt(u32 fmt)
{
	return fmt == NET_DMQ_FMT_BNXT_P5 || fmt == NET_DMQ_FMT_BNXT_P7;
}

#define KNOD_GDA_ENTRY_OFFSET		1024
/*
 * XDP_PASS: a queue's VRAM staging slots, a page each and a PASS ring entry
 * each - 32 MB of VRAM, fewer slots as big as an RX buffer if that is more
 * than a page - and the entries the worker takes in one SDMA job.  A packet
 * goes in its host page after NET_SKB_PAD of headroom.
 */
#define KNOD_GDA_PASS_SLOTS		8192
#define KNOD_GDA_PASS_RING_BYTES	(KNOD_GDA_PASS_SLOTS * 8)
#define KNOD_GDA_PASS_BATCH		256
#define KNOD_GDA_PASS_HEAD		NET_SKB_PAD
static_assert(KNOD_GDA_PASS_SLOTS <= KNOD_PERSIST_GDA_PASS_ENTRIES);
/* Host TX: slots a queue's buffer has, a page each - fewer and bigger
 * with bigger RX buffers - then its ring and counters.
 */
#define KNOD_GDA_HTX_SLOTS		2048
#define KNOD_GDA_HTX_RING_OFF		((size_t)KNOD_GDA_HTX_SLOTS << PAGE_SHIFT)
#define KNOD_GDA_HTX_CTL_OFF		(KNOD_GDA_HTX_RING_OFF + \
					 KNOD_GDA_HTX_SLOTS * 8)
#define KNOD_GDA_HTX_BYTES		(KNOD_GDA_HTX_CTL_OFF + 2 * SMP_CACHE_BYTES)
/* The largest RX buffer, as the NIC's. */
#define KNOD_GDA_SLOT_MAX		SZ_16K
static_assert(KNOD_PERSIST_HTX_CC + 4 <= 2 * SMP_CACHE_BYTES);

/* HDP 5.0.3 can serve stale shader-written VRAM TX WQEs to the NIC.
 * The cache switch is per GPU, so restore it only after its last GDA stops.
 */
static DEFINE_MUTEX(knod_gda_hdp_lock);
static LIST_HEAD(knod_gda_hdp_users);

static struct amdgpu_device *knod_gda_adev(struct knod_gda *g)
{
	return g->knod->process->pdds[0]->dev->adev;
}

static int knod_gda_hdp_cache_disable(struct knod_gda *g)
{
	struct amdgpu_device *adev = knod_gda_adev(g);
	struct knod_gda *other;
	u32 value;

	if (amdgpu_ip_version(adev, HDP_HWIP, 0) != IP_VERSION(5, 0, 3))
		return 0;
	mutex_lock(&knod_gda_hdp_lock);
	if (g->hdp_cache_disabled)
		goto out;

	value = RREG32_SOC15_NO_KIQ(HDP, 0, mmHDP_HOST_PATH_CNTL);
	g->hdp_restore_read_cache =
		!(value & HDP_HOST_PATH_CNTL__LIN_RD_CACHE_DIS_MASK);
	list_for_each_entry(other, &knod_gda_hdp_users, hdp_link) {
		if (knod_gda_adev(other) == adev) {
			g->hdp_restore_read_cache = other->hdp_restore_read_cache;
			break;
		}
	}
	WREG32_SOC15_NO_KIQ(HDP, 0, mmHDP_HOST_PATH_CNTL,
			      value | HDP_HOST_PATH_CNTL__LIN_RD_CACHE_DIS_MASK);
	value = RREG32_SOC15_NO_KIQ(HDP, 0, mmHDP_HOST_PATH_CNTL);
	if (!(value & HDP_HOST_PATH_CNTL__LIN_RD_CACHE_DIS_MASK)) {
		mutex_unlock(&knod_gda_hdp_lock);
		return -EIO;
	}
	list_add(&g->hdp_link, &knod_gda_hdp_users);
	g->hdp_cache_disabled = true;
out:
	mutex_unlock(&knod_gda_hdp_lock);
	return 0;
}

static void knod_gda_hdp_cache_restore(struct knod_gda *g)
{
	struct amdgpu_device *adev;
	struct knod_gda *other;
	u32 value;

	mutex_lock(&knod_gda_hdp_lock);
	if (!g->hdp_cache_disabled)
		goto out;
	adev = knod_gda_adev(g);
	list_del_init(&g->hdp_link);
	g->hdp_cache_disabled = false;
	list_for_each_entry(other, &knod_gda_hdp_users, hdp_link)
		if (knod_gda_adev(other) == adev)
			goto out;

	value = RREG32_SOC15_NO_KIQ(HDP, 0, mmHDP_HOST_PATH_CNTL);
	if (g->hdp_restore_read_cache)
		value &= ~HDP_HOST_PATH_CNTL__LIN_RD_CACHE_DIS_MASK;
	else
		value |= HDP_HOST_PATH_CNTL__LIN_RD_CACHE_DIS_MASK;
	WREG32_SOC15_NO_KIQ(HDP, 0, mmHDP_HOST_PATH_CNTL, value);
	value = RREG32_SOC15_NO_KIQ(HDP, 0, mmHDP_HOST_PATH_CNTL);
	if (!!(value & HDP_HOST_PATH_CNTL__LIN_RD_CACHE_DIS_MASK) ==
	    g->hdp_restore_read_cache)
		pr_warn("knod: failed to restore HDP read cache setting\n");
out:
	mutex_unlock(&knod_gda_hdp_lock);
}

static struct knod_persistent_mem *knod_gda_mem(struct knod_gda *g)
{
	return g->control->kaddr;
}

/* Queue @q's PASS ring in pass_rings, and after it, on a cache line of
 * their own, the count of entries the shader appended and at
 * KNOD_PERSIST_PASS_CC the count the host is done with.
 */
#define KNOD_GDA_PASS_STRIDE	(KNOD_GDA_PASS_RING_BYTES + SMP_CACHE_BYTES)

static size_t knod_gda_pass_ring_off(u32 q)
{
	return (size_t)q * KNOD_GDA_PASS_STRIDE;
}

static u32 knod_gda_pass_pc(struct knod_gda *g, u32 q)
{
	return READ_ONCE(*(u32 *)(g->pass_rings->kaddr +
				  knod_gda_pass_ring_off(q) +
				  g->pass_slots * 8));
}

/* Where queue @q's count of PASS entries the host is done with is. */
static u32 *knod_gda_pass_cc_ptr(struct knod_gda *g, u32 q)
{
	return g->pass_rings->kaddr + knod_gda_pass_ring_off(q) +
	       g->pass_slots * 8 + KNOD_PERSIST_PASS_CC;
}

static u32 knod_gda_pass_cc(struct knod_gda *g, u32 q)
{
	if (!g->pass_rings)
		return 0;
	return READ_ONCE(*knod_gda_pass_cc_ptr(g, q));
}

/* Queue @q's delivery entries to the NIC's drain. */
static void knod_gda_pass_publish(struct knod_gda *g, u32 q)
{
	/* Their counts set when they were made, before the entries. */
	smp_store_release(&g->knodev->wpriv[q].pass_buf, g->pass_buf[q]);
}

/* Where the host TX counts are, past the ring's entries. */
static size_t knod_gda_htx_ctl_off(struct knod_gda *g)
{
	return KNOD_GDA_HTX_RING_OFF + (size_t)g->htx_slots * 8;
}

/*
 * A packet's RX buffer: the smallest power of two of pages its frame fits
 * in, with the headroom before it and the skb's tail after.  Set as the
 * queues are handed over; an MTU raised past it later leaves them unrun.
 * bnxt puts a bigger frame's rest elsewhere: a page.
 */
static u32 knod_gda_slot_shift(struct knod_gda *g)
{
	u32 need = XDP_PACKET_HEADROOM + NET_IP_ALIGN + VLAN_ETH_HLEN +
		   VLAN_HLEN + ETH_FCS_LEN +
		   READ_ONCE(g->knodev->netdev->mtu) +
		   SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

	if (knod_gda_fmt_bnxt(g->fmt))
		return PAGE_SHIFT;
	return clamp_t(u32, order_base_2(need), PAGE_SHIFT,
		       ilog2(KNOD_GDA_SLOT_MAX));
}

/* No drain on the PASS rings any more before they go. */
static void knod_gda_pass_unpublish(struct knod_gda *g)
{
	int i;

	for (i = 0; i < KNOD_SPSC_MAX; i++)
		WRITE_ONCE(g->knodev->wpriv[i].pass_buf, NULL);
	/* A NAPI poll that saw a ring is done with it. */
	synchronize_net();
}

static unsigned int knod_gda_active_rxq_count(struct net_device *netdev)
{
	unsigned int nr_rxq;

	struct ethtool_channels ch = {};

	/* The channels as set: down, real_num_rx_queues is still every queue
	 * the device was allocated with.
	 */
	if (netdev->ethtool_ops && netdev->ethtool_ops->get_channels) {
		netdev->ethtool_ops->get_channels(netdev, &ch);
		nr_rxq = ch.combined_count + ch.rx_count;
		if (nr_rxq)
			return nr_rxq;
	}
	nr_rxq = READ_ONCE(netdev->real_num_rx_queues);
	if (!nr_rxq)
		nr_rxq = netdev->num_rx_queues;
	return nr_rxq;
}

static int knod_gda_geometry_check(struct knod *knod, u32 wg_size)
{
	u32 waves = DIV_ROUND_UP(wg_size, 64);
	u32 vgpr_waves, topology_waves;

	if (!knod->simd_per_cu || !knod->max_waves_per_simd ||
	    !knod->vgpr_size_per_cu)
		return -EOPNOTSUPP;

	topology_waves = knod->simd_per_cu * knod->max_waves_per_simd;
	vgpr_waves = knod->vgpr_size_per_cu /
		(KNOD_GDA_VGPR_COUNT * 64 * sizeof(u32));
	if (waves > min(topology_waves, vgpr_waves)) {
		pr_warn("knod: a %u-lane workgroup needs %u resident waves, only %u fit\n",
			wg_size, waves, min(topology_waves, vgpr_waves));
		return -E2BIG;
	}
	return 0;
}

/*
 * The descriptor every kernel the engine runs shares.  gfx10 and gfx11 want
 * the same one: every field that is per generation - the VGPR granule, the
 * reserved SGPR count, wave size, mem_ordered - has the same value on both.
 */
/*
 * Debug: an empty kernel - s_endpgm alone - dispatched on AQL queue @q and
 * waited for on its completion signal, again and again: what a dispatch
 * costs before any work, by workgroups in the grid.  For a context whose
 * queue @q nothing else uses, a standalone one's.
 */
int knod_dispatch_bench(struct seq_file *s, struct knod *knod, int q)
{
	static const u32 grids[] = { 1, 64, 1024 };
	struct amdgpu_device *adev = knod->process->pdds[0]->dev->adev;
	struct knod_dispatch_params p = {};
	u64 t, best, sum, end, sig_gaddr;
	struct kernel_descriptor *kd;
	struct amd_signal *sig;
	struct knod_mem *code;
	int g, r, n = 200, err = 0;
	u32 *insn, i;

	if (q < 0 || q >= knod->queue_cnt)
		return -EINVAL;
	code = knod_alloc_mem(knod, PAGE_SIZE, KFD_IOC_ALLOC_MEM_FLAGS_VRAM |
			      KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
			      KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE);
	if (IS_ERR(code))
		return PTR_ERR(code);
	kd = code->kaddr;
	memset(kd, 0, sizeof(*kd));
	kd->kernel_code_entry_byte_offset = 256;
	kd->compute_pgm_rsrc1.float_denorm_mode_32 = 3;
	kd->compute_pgm_rsrc1.float_denorm_mode_16_64 = 3;
	kd->compute_pgm_rsrc1.enable_dx10_clamp = 1;
	kd->compute_pgm_rsrc1.enable_ieee_mode = 1;
	kd->compute_pgm_rsrc1.mem_ordered = 1;
	/* s_endpgm, and more of it where a prefetch might look. */
	insn = code->kaddr + 256;
	for (i = 0; i < 16; i++)
		insn[i] = knod->isa_version >= 11 ? 0xbfb00000 : 0xbf810000;
	/* The code, written through the BAR, out of the HDP before a wave
	 * fetches it.
	 */
	wmb();
	amdgpu_device_flush_hdp(adev, NULL);

	sig = knod->kaql[q].queue_signal->kaddr;
	sig_gaddr = knod->kaql[q].queue_signal->gaddr;
	p.workgroup_size_x = 64;
	p.grid_size_y = 1;
	p.kernel_object = code->gaddr;
	p.kernarg_address = code->gaddr;
	for (g = 0; g < ARRAY_SIZE(grids); g++) {
		p.grid_size_x = grids[g] * 64;
		best = U64_MAX;
		sum = 0;
		for (r = 0; r < n; r++) {
			WRITE_ONCE(sig->value, 1);
			/* The signal armed before the packet that ends it. */
			wmb();
			t = ktime_get_ns();
			knod_setup_header_signal(knod, &p, q, sig_gaddr);
			end = t + 100 * NSEC_PER_MSEC;
			while (READ_ONCE(sig->value) > 0 && ktime_get_ns() < end)
				cpu_relax();
			if (READ_ONCE(sig->value) > 0) {
				seq_printf(s, "grid %u: no completion in 100 ms\n",
					   grids[g]);
				err = -ETIMEDOUT;
				goto out;
			}
			t = ktime_get_ns() - t;
			best = min(best, t);
			sum += t;
		}
		seq_printf(s, "empty dispatch, %4u workgroups: best %llu ns, avg %llu ns (%d runs)\n",
			   grids[g], best, sum / n, n);
	}
out:
	knod_free_mem(knod, code);
	return err;
}
EXPORT_SYMBOL_GPL(knod_dispatch_bench);

static void knod_gda_write_descriptor(struct knod *knod)
{
	struct kernel_descriptor *kd = knod->kernel->kaddr;

	memset(kd, 0, sizeof(*kd));
	kd->kernarg_size = 64;
	kd->kernel_code_entry_byte_offset = KNOD_GDA_ENTRY_OFFSET;

	/*
	 * User SGPRs load in this order, disabled ones skipped: private
	 * segment buffer s[0:3], dispatch s[4:5], queue s[6:7], kernarg
	 * s[8:9], dispatch id s[10:11].  The workgroup ids follow at s12
	 * and s13, and on gfx10 the wave's offset into the scratch ring at
	 * s14, which the blob turns into FLAT_SCRATCH before anything else
	 * takes the register.
	 */
	kd->code_properties.enable_sgpr_private_segment_buffer = 1;
	kd->code_properties.enable_sgpr_dispatch_ptr = 1;
	kd->code_properties.enable_sgpr_queue_ptr = 1;
	kd->code_properties.enable_sgpr_kernarg_segment_ptr = 1;
	kd->code_properties.enable_sgpr_dispatch_id = 1;

	kd->compute_pgm_rsrc1.granulated_workitem_vgpr_count =
		(KNOD_GDA_VGPR_COUNT / 4) - 1;
	kd->compute_pgm_rsrc1.float_denorm_mode_32 = 3;
	kd->compute_pgm_rsrc1.float_denorm_mode_16_64 = 3;
	kd->compute_pgm_rsrc1.enable_dx10_clamp = 1;
	kd->compute_pgm_rsrc1.enable_ieee_mode = 1;
	/* CU mode.  A resident workgroup has to fit one CU for the admission
	 * check to be able to promise it stays resident, and it is the faster
	 * placement anyway: its waves share one CU's cache instead of
	 * spreading over both halves of a WGP.  30 Mpps against 20, RDNA2.
	 */
	kd->compute_pgm_rsrc1.wgp_mode = 0;
	kd->compute_pgm_rsrc1.mem_ordered = 1;

	kd->compute_pgm_rsrc2.user_sgpr_count = 12;
	/* Scratch, for a BPF stack too deep for LDS. */
	kd->compute_pgm_rsrc2.enable_private_segment = 1;
	kd->private_segment_fixed_size = KNOD_SCRATCH_BYTES_PER_LANE;
	kd->compute_pgm_rsrc2.enable_sgpr_workgroup_id_x = 1;
	kd->compute_pgm_rsrc2.enable_sgpr_workgroup_id_y = 1;
	kd->compute_pgm_rsrc2.enable_vgpr_workitem_id = 1;
}

/*
 * @size bytes of a kernel's code at a context's kernel object, behind the
 * GDA engine's kernel descriptor: for a standalone context, whose object no
 * engine has.  Dispatch it at knod->kernel->gaddr.
 */
int knod_kernel_install(struct knod *knod, const void *code, u32 size)
{
	if (!code || size > knod->kernel->size - KNOD_GDA_ENTRY_OFFSET)
		return -EINVAL;
	knod_gda_write_descriptor(knod);
	memcpy_toio((void __iomem *)knod->kernel->kaddr + KNOD_GDA_ENTRY_OFFSET,
		    code, size);
	knod_hdp_flush(knod);
	return 0;
}
EXPORT_SYMBOL_GPL(knod_kernel_install);

/* CPU writes to VRAM through the BAR, out of the HDP for the GPU to see. */
void knod_hdp_flush(struct knod *knod)
{
	wmb();
	amdgpu_device_flush_hdp(knod->process->pdds[0]->dev->adev, NULL);
}
EXPORT_SYMBOL_GPL(knod_hdp_flush);

static void knod_gda_shader_stop(struct knod_gda *g,
				 enum knod_gda_stop_reason reason)
{
	struct knod_persistent_mem *mem = knod_gda_mem(g);
	unsigned long deadline;
	bool warned = false;

	if (!g->running)
		return;
	might_sleep();
	dma_wmb();
	writel(1, (void __iomem *)&mem->control.stop);
	/* Publish CPU BAR writes before the shader consumes them. */
	wmb();
	amdgpu_device_flush_hdp(knod_gda_adev(g), NULL);
	deadline = jiffies + msecs_to_jiffies(1000);
	while (readq((void __iomem *)&mem->terminal.value)) {
		if (!warned && time_after(jiffies, deadline)) {
			pr_warn("knod: retaining persistent shader backing pending terminal completion\n");
			warned = true;
		}
		usleep_range(100, 200);
	}
	dma_rmb();
	g->running = false;
	g->stops++;
	g->stop_reasons[reason]++;
}

static void knod_gda_shader_start(struct knod_gda *g)
{
	struct knod_dispatch_params p = {};
	u64 completion_signal;

	WARN_ON_ONCE(g->running);
	p.workgroup_size_x = g->wg_size;
	p.grid_size_x = g->wg_size;
	p.grid_size_y = g->nr_queues;
	p.group_segment_size = g->lds_bytes + g->engine.lds_bytes;
	p.private_segment_size = KNOD_SCRATCH_BYTES_PER_LANE;
	p.kernel_object = g->knod->kernel->gaddr;
	p.kernarg_address = g->control->gaddr;
	completion_signal = g->control->gaddr +
		offsetof(struct knod_persistent_mem, terminal);
	/* All control initialization precedes launch. */
	wmb();
	/* The code and control the CPU just wrote went through the BAR: out of
	 * the HDP before a wave fetches them, or it can run half the old code.
	 */
	amdgpu_device_flush_hdp(g->knod->process->pdds[0]->dev->adev, NULL);
	knod_setup_header_signal(g->knod, &p, 0, completion_signal);
	g->running = true;
	g->launches++;
}

/*
 * Offer the NIC each queue's ring buffer and XDP SQ buffer in accel memory,
 * and give the shader the NIC's address for every RX page it may send from,
 * and the block a program's context lives in, with the PASS rings past it.
 * The NIC builds its queues on them when it next brings the interface up.
 */
/*
 * The NIC's queues, handed to the engine.  The engine reads the rings at
 * fixed places in each queue's ring buffer (KNOD_PERSIST_RING_*), so those
 * are where the NIC must build them: the regions say so, and the rings it
 * reports are checked against them again before the engine is told.
 */
static const struct net_dmq_region knod_gda_mlx5_regions[] = {
	[NET_DMQ_MLX5_RQ]	= { KNOD_GDA_RQ_OFF, KNOD_GDA_RQ_BYTES },
	[NET_DMQ_MLX5_RX_CQ]	= { KNOD_GDA_CQ_OFF, KNOD_GDA_CQ_BYTES },
	[NET_DMQ_MLX5_SQ]	= { KNOD_GDA_SQ_OFF, KNOD_GDA_SQ_BYTES },
	[NET_DMQ_MLX5_TX_CQ]	= { KNOD_GDA_TX_CQ_OFF, KNOD_GDA_TX_CQ_BYTES },
	[NET_DMQ_MLX5_DBR]	= { KNOD_GDA_DB_OFF, PAGE_SIZE },
};

static_assert(ARRAY_SIZE(knod_gda_mlx5_regions) == NET_DMQ_MLX5_RINGS);
static_assert(NET_DMQ_MLX5_RQ_DBR == KNOD_PERSIST_RING_RQ_DB);
static_assert(NET_DMQ_MLX5_CQ_DBR == KNOD_PERSIST_RING_CQ_DB);
static_assert(NET_DMQ_MLX5_SQ_DBR + 4 == KNOD_PERSIST_RING_SQ_DB);
static_assert(NET_DMQ_MLX5_TX_CQ_DBR == KNOD_PERSIST_RING_TX_CQ_DB);
static_assert(KNOD_GDA_RQPOS_OFF + KNOD_GDA_RQPOS_BYTES <= KNOD_GDA_SQ_OFF);

/* bnxt's: the same places, less the doorbell records it has none of. */
static const struct net_dmq_region knod_gda_bnxt_regions[] = {
	[NET_DMQ_BNXT_RQ]	= { KNOD_GDA_RQ_OFF, KNOD_GDA_RQ_BYTES },
	[NET_DMQ_BNXT_RX_CQ]	= { KNOD_GDA_CQ_OFF, KNOD_GDA_CQ_BYTES },
	[NET_DMQ_BNXT_SQ]	= { KNOD_GDA_SQ_OFF, KNOD_GDA_SQ_BYTES },
	[NET_DMQ_BNXT_TX_CQ]	= { KNOD_GDA_TX_CQ_OFF, KNOD_GDA_TX_CQ_BYTES },
};

static_assert(ARRAY_SIZE(knod_gda_bnxt_regions) == NET_DMQ_BNXT_RINGS);

/* The engine reads only the formats it was built for. */
static const struct net_dmq_region *knod_gda_regions(u32 fmt, u32 *nr)
{
	switch (fmt) {
	case NET_DMQ_FMT_MLX5_CX5:
		*nr = ARRAY_SIZE(knod_gda_mlx5_regions);
		return knod_gda_mlx5_regions;
	case NET_DMQ_FMT_BNXT_P5:
	case NET_DMQ_FMT_BNXT_P7:
		*nr = ARRAY_SIZE(knod_gda_bnxt_regions);
		return knod_gda_bnxt_regions;
	}
	return NULL;
}

/* A queue is built, or built again: what it is, for the next shader start.
 * The NIC's driver calls this as it activates the queue, and starts the
 * engine after.
 */
static bool knod_gda_all_up(struct knod_gda *g)
{
	int i;

	for (i = 0; i < g->nr_queues; i++)
		if (!READ_ONCE(g->q[i].up))
			return false;
	return true;
}

/*
 * The NIC rebuilt its queues - new channels, a reset - with the interface
 * up all along: the engine back onto them, as an interface up would.
 */
static void knod_gda_restart(struct work_struct *work)
{
	struct knod_gda *g = container_of(work, struct knod_gda, restart);

	if (READ_ONCE(g->want) && READ_ONCE(g->ready) &&
	    !READ_ONCE(g->running))
		knod_gda_start(g->knod);
}

static void knod_gda_queue_up(struct net_devmem_queue *q,
			      const struct net_dmq_info *info, void *priv)
{
	struct knod_gda *g = priv;
	u32 i = net_dmq_queue_idx(q);

	if (WARN_ON_ONCE(i >= KNOD_SPSC_MAX))
		return;
	g->q[i].info = *info;
	smp_wmb();	/* the info before up; pairs with the start's read */
	WRITE_ONCE(g->q[i].up, true);
	if (READ_ONCE(g->want) && !READ_ONCE(g->running) &&
	    knod_gda_all_up(g))
		schedule_work(&g->restart);
}

/* Off the queue before the NIC tears it down: the driver stops the engine
 * first, as it brings the interface down; if it did not, stop it here.
 */
static void knod_gda_queue_down(struct net_devmem_queue *q, void *priv)
{
	struct knod_gda *g = priv;
	u32 i = net_dmq_queue_idx(q);

	if (i < KNOD_SPSC_MAX)
		WRITE_ONCE(g->q[i].up, false);
	if (READ_ONCE(g->running))
		knod_gda_stop(g->knod);
}

static void knod_gda_queue_dead(struct net_devmem_queue *q, void *priv)
{
	struct knod_gda *g = priv;

	pr_warn("knod: %s queue %u is gone\n", netdev_name(g->knodev->netdev),
		net_dmq_queue_idx(q));
	knod_gda_queue_down(q, priv);
}

static const struct net_dmq_ops knod_gda_queue_ops = {
	.up = knod_gda_queue_up,
	.down = knod_gda_queue_down,
	.dead = knod_gda_queue_dead,
};

static int knod_gda_bind(struct knod_gda *g)
{
	const struct net_dmq_region *regions;
	struct net_devmem_queue_binding *binding;
	struct netlink_ext_ack extack = {};
	struct net_dmq_bind_req *reqs;
	struct knod *knod = g->knod;
	u32 nr_regions, i;
	int err = 0;

	regions = knod_gda_regions(g->fmt, &nr_regions);
	if (!regions)
		return -EOPNOTSUPP;
	reqs = kcalloc(g->nr_queues, sizeof(*reqs), GFP_KERNEL);
	if (!reqs)
		return -ENOMEM;
	for (i = 0; i < g->nr_queues; i++) {
		if (knod->gda_rx[i]->size < KNOD_GDA_RING_BYTES) {
			err = -EINVAL;
			goto out;
		}
		reqs[i].idx = i;
		reqs[i].rings = knod->gda_rx[i]->mem->dmabuf;
		reqs[i].data = knod->buf[i]->mem->dmabuf;
		reqs[i].nr_regions = nr_regions;
		memcpy(reqs[i].region, regions, nr_regions * sizeof(*regions));
	}
	binding = net_devmem_bind_queues(g->knodev->netdev, reqs,
					 g->nr_queues, &knod_gda_queue_ops, g,
					 &extack);
	if (IS_ERR(binding)) {
		err = PTR_ERR(binding);
		pr_warn("knod: %s will not hand its queues over: %d (%s)\n",
			netdev_name(g->knodev->netdev), err,
			extack._msg ?: "no reason given");
		goto out;
	}
	g->binding = binding;
out:
	kfree(reqs);
	return err;
}

/* What the NIC says of a queue, against what the engine reads: the rings
 * where the regions put them, of sizes the engine's masks and the buffers
 * hold.  A queue that fails is not run.
 */
static bool knod_gda_queue_ok(struct knod_gda *g, int i)
{
	const struct net_dmq_info *info = &g->q[i].info;
	const struct net_dmq_bnxt *b = (const void *)info->fmt_priv;
	const struct net_dmq_region *regions;
	bool bnxt = knod_gda_fmt_bnxt(g->fmt);
	u32 nr, r, entries, posted;

	/* Somewhere to copy what passes to. */
	if (!g->pass_stage[i])
		return false;
	regions = knod_gda_regions(g->fmt, &nr);
	if (!regions || info->fmt != g->fmt || info->nr_rings != nr ||
	    info->data_addr != (bnxt ? NET_DMQ_DATA_BUS : NET_DMQ_DATA_OFFSET))
		return false;
	for (r = 0; r < nr; r++) {
		entries = info->ring[r].entries;
		if (info->ring[r].offset != regions[r].offset)
			return false;
		if (!bnxt && r == NET_DMQ_MLX5_DBR)
			continue;
		if (!entries || !is_power_of_2(entries) ||
		    !is_power_of_2(info->ring[r].stride) ||
		    (u64)entries * info->ring[r].stride > regions[r].bytes)
			return false;
	}
	/* bnxt posts fewer RQ entries than it has, the engine one SQ entry
	 * per RQPOS slot.
	 */
	posted = info->ring[NET_DMQ_MLX5_RQ].entries;
	if (bnxt) {
		posted = b->rq_posted;
		if (!posted || !is_power_of_2(posted) ||
		    posted >= info->ring[NET_DMQ_BNXT_RQ].entries)
			return false;
	}
	if (info->ring[bnxt ? NET_DMQ_BNXT_SQ : NET_DMQ_MLX5_SQ].entries >
	    KNOD_GDA_RQPOS_BYTES / 4)
		return false;
	/* Every RX buffer the RQ posts is one of the buffer's. */
	return posted <= g->knod->buf[i]->size >> g->slot_shift;
}

/*
 * Each queue's PASS staging in VRAM, contiguous for the kernel's SDMA to
 * read by one address, the page_pool its packets go to the stack in, and
 * the entries the NIC's drain takes them from; and SDMA entities of our own
 * for the copies.
 */
static int knod_gda_pass_init(struct knod_gda *g)
{
	struct amdgpu_device *adev = knod_gda_adev(g);
	struct page_pool_params pp = {
		.flags = PP_FLAG_DMA_MAP,
		.order = g->slot_shift - PAGE_SHIFT,
		.nid = NUMA_NO_NODE,
		.dev = adev->dev,
		.dma_dir = DMA_FROM_DEVICE,
	};
	struct knod_work_priv *wpriv;
	struct knod_mem *mem;
	size_t size = (size_t)KNOD_GDA_PASS_SLOTS << PAGE_SHIFT;
	int i, n;

	g->pass_slots = size >> g->slot_shift;
	pp.pool_size = g->pass_slots;
	n = knod_ksdma_entities_init(adev, g->pass_ent, KNOD_HTX_SDMA_RINGS);
	if (n < 0)
		return n;
	g->pass_nent = n;
	for (i = 0; i < g->nr_queues; i++) {
		mem = knod_alloc_mem(g->knod, size,
				     KFD_IOC_ALLOC_MEM_FLAGS_VRAM |
				     KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
				     KFD_IOC_ALLOC_MEM_FLAGS_CONTIGUOUS);
		if (IS_ERR_OR_NULL(mem))
			return -ENOMEM;
		g->pass_stage[i] = mem;
		g->pass_stage_mc[i] = knod_vram_mc(adev, mem, 0);
		if (!g->pass_stage_mc[i] ||
		    knod_vram_mc(adev, mem, size - PAGE_SIZE) !=
		    g->pass_stage_mc[i] + size - PAGE_SIZE) {
			pr_warn("knod: queue %d PASS staging not contiguous\n",
				i);
			return -EINVAL;
		}
		g->pass_pool[i] = page_pool_create(&pp);
		if (IS_ERR(g->pass_pool[i])) {
			g->pass_pool[i] = NULL;
			return -ENOMEM;
		}
		g->pass_buf[i] = kvcalloc(g->pass_slots,
					  sizeof(*g->pass_buf[i]), GFP_KERNEL);
		if (!g->pass_buf[i])
			return -ENOMEM;
		g->pass_seen[i] = 0;
		g->pass_res[i] = 0;
		wpriv = &g->knodev->wpriv[i];
		wpriv->pass_mask = g->pass_slots - 1;
		wpriv->pass_pc = 0;
		wpriv->pass_cc = 0;
	}
	return 0;
}

/*
 * The other way, the drain unpublished first: every job done - its pages
 * filled, its callback run - then what no drain took back to the pools.
 */
static void knod_gda_pass_exit(struct knod_gda *g)
{
	struct knod_work_priv *wpriv;
	struct knod_pass_buf *b;
	u32 cc;
	int i;

	knod_ksdma_entities_fini(g->pass_ent, g->pass_nent);
	g->pass_nent = 0;
	wait_var_event(&g->pass_jobs, !atomic_read(&g->pass_jobs));
	for (i = 0; i < KNOD_SPSC_MAX; i++) {
		wpriv = &g->knodev->wpriv[i];
		if (g->pass_buf[i]) {
			for (cc = wpriv->pass_cc; cc != g->pass_res[i]; cc++) {
				b = &g->pass_buf[i][cc & (g->pass_slots - 1)];
				if (b->page)
					page_pool_put_full_page(g->pass_pool[i],
								b->page, false);
				b->page = NULL;
			}
			wpriv->pass_cc = g->pass_res[i];
			wpriv->pass_pc = g->pass_res[i];
		}
		kvfree(g->pass_buf[i]);
		g->pass_buf[i] = NULL;
		if (g->pass_pool[i])
			page_pool_destroy(g->pass_pool[i]);
		g->pass_pool[i] = NULL;
		if (g->pass_stage[i])
			knod_free_mem(g->knod, g->pass_stage[i]);
		g->pass_stage[i] = NULL;
	}
}

/*
 * A PASS job: the queues of one SDMA entity it took entries of, each with
 * the shader's entries up to @pc and the drain's up to @res once it is done.
 */
struct knod_gda_pass_job {
	struct dma_fence_cb cb;
	struct knod_gda *g;
	u32 nq;
	struct {
		u32 q, pc, res;
	} part[KNOD_SPSC_MAX];
};

/*
 * Queue @q's entries up to @res the drain's - their pages filled - and the
 * shader's slots up to @pc its own again, copied out of.
 */
static void knod_gda_pass_deliver(struct knod_gda *g, u32 q, u32 pc, u32 res)
{
	WRITE_ONCE(*knod_gda_pass_cc_ptr(g, q), pc);
	/* The pages' contents and entries before the count that hands them
	 * over, which the drain acquires.
	 */
	smp_store_release(&g->knodev->wpriv[q].pass_pc, res);
	knod_dev_pass_kick(g->knodev, q);
}

static void knod_gda_pass_done(struct dma_fence *f, struct dma_fence_cb *cb)
{
	struct knod_gda_pass_job *job = container_of(cb, typeof(*job), cb);
	struct knod_gda *g = job->g;
	u32 i;

	for (i = 0; i < job->nq; i++) {
		knod_gda_pass_deliver(g, job->part[i].q, job->part[i].pc,
				      job->part[i].res);
		atomic_dec(&g->pass_qjobs[job->part[i].q]);
	}
	kfree(job);
	if (atomic_dec_and_test(&g->pass_jobs))
		wake_up_var(&g->pass_jobs);
}

/* How many of queue @q's new entries a job may take now, up to @max. */
static u32 knod_gda_pass_avail(struct knod_gda *g, u32 q, u32 max)
{
	/* The drain's entries free once it has let go of their pages. */
	u32 cc = smp_load_acquire(&g->knodev->wpriv[q].pass_cc);

	return min3(knod_gda_pass_pc(g, q) - g->pass_seen[q], max,
		    g->pass_slots - (g->pass_res[q] - cc));
}

/*
 * Up to @n of queue @q's new entries into job @sb: a page of the queue's
 * pool for each and a copy from its staging slot to the page through the
 * AGP aperture.  Returns the entries taken - fewer when pages run out -
 * and adds the copies to *@copies.
 */
static u32 knod_gda_pass_fill(struct knod_gda *g, struct knod_ksdma_batch *sb,
			      u32 q, u32 n, u32 *copies)
{
	struct amdgpu_device *adev = knod_gda_adev(g);
	const u64 *ring = g->pass_rings->kaddr + knod_gda_pass_ring_off(q);
	const u32 mask = g->pass_slots - 1, size = 1U << g->slot_shift;
	u32 taken = g->pass_seen[q], res = g->pass_res[q], i, slot;
	struct knod_pass_buf *b;
	struct page *page;
	u16 off, len;
	u64 v, dst;

	/* The entries' slots before what the shader put in them. */
	smp_rmb();
	for (i = 0; i < n; i++) {
		slot = (taken + i) & mask;
		v = READ_ONCE(ring[slot]);
		off = v >> 32 & 0xffff;
		len = v >> 48;
		b = &g->pass_buf[q][res & mask];
		b->page = NULL;
		if (len >= ETH_HLEN && off + len <= size &&
		    len <= size - KNOD_GDA_PASS_HEAD) {
			page = page_pool_alloc_pages(g->pass_pool[q],
						     GFP_KERNEL | __GFP_NOWARN);
			if (!page)
				break;
			dst = knod_agp_addr(adev, page_pool_get_dma_addr(page) +
					    KNOD_GDA_PASS_HEAD, len);
			if (dst == KNOD_AGP_NONE) {
				page_pool_put_full_page(g->pass_pool[q], page,
							false);
			} else {
				knod_ksdma_copy(sb, g->pass_stage_mc[q] +
						((u64)slot << g->slot_shift) + off,
						dst, len);
				b->page = page;
				b->v = (u64)(KNOD_GDA_PASS_HEAD |
					     (u32)len << 16) << 32 | (u32)v;
				(*copies)++;
			}
		}
		res++;
	}
	g->pass_seen[q] = taken + i;
	g->pass_res[q] = res;
	return i;
}

/*
 * Every new PASS entry of the queues on SDMA entity @ent - q % pass_nent -
 * in one job: a job's fixed cost, its scheduling, fence and interrupt, is
 * spread over all of them instead of paid a queue.  A queue's jobs stay on
 * its entity, so they complete, and deliver, in order.  Returns how many
 * entries it took.
 */
#define KNOD_GDA_PASS_JOB_MAX	2048

static u32 knod_gda_pass_job(struct knod_gda *g, int ent)
{
	u32 avail[KNOD_SPSC_MAX], seen[KNOD_SPSC_MAX], res[KNOD_SPSC_MAX];
	u32 bound = 0, total = 0, copies = 0, part, n, i;
	struct knod_gda_pass_job *job;
	struct knod_ksdma_batch sb;
	struct dma_fence *fence;
	int q;

	for (q = ent; q < g->nr_queues; q += g->pass_nent) {
		avail[q] = g->pass_buf[q] ?
			   knod_gda_pass_avail(g, q, KNOD_GDA_PASS_JOB_MAX -
						     bound) : 0;
		bound += avail[q];
	}
	if (!bound)
		return 0;
	job = kmalloc_obj(*job, GFP_KERNEL);
	if (!job)
		return 0;
	if (knod_ksdma_begin(&sb, knod_gda_adev(g), &g->pass_ent[ent], bound,
			     0)) {
		kfree(job);
		return 0;
	}
	job->g = g;
	job->nq = 0;
	for (q = ent; q < g->nr_queues; q += g->pass_nent) {
		if (!avail[q])
			continue;
		seen[q] = g->pass_seen[q];
		res[q] = g->pass_res[q];
		n = knod_gda_pass_fill(g, &sb, q, avail[q], &copies);
		if (!n)
			continue;
		total += n;
		job->part[job->nq].q = q;
		job->part[job->nq].pc = g->pass_seen[q];
		job->part[job->nq].res = g->pass_res[q];
		job->nq++;
	}
	if (!copies) {
		knod_ksdma_abort(&sb);
		/* Entries with nothing to copy, dropped: delivered at once -
		 * unless a job of the queue's is still out, which they would
		 * pass, and then taken again later.
		 */
		for (part = 0; part < job->nq; part++) {
			q = job->part[part].q;
			if (atomic_read(&g->pass_qjobs[q])) {
				total -= job->part[part].pc - seen[q];
				g->pass_seen[q] = seen[q];
				g->pass_res[q] = res[q];
				continue;
			}
			knod_gda_pass_deliver(g, q, job->part[part].pc,
					      job->part[part].res);
		}
		kfree(job);
		return total;
	}
	atomic_inc(&g->pass_jobs);
	for (i = 0; i < job->nq; i++)
		atomic_inc(&g->pass_qjobs[job->part[i].q]);
	fence = knod_ksdma_submit(&sb);
	if (dma_fence_add_callback(fence, &job->cb, knod_gda_pass_done))
		knod_gda_pass_done(fence, &job->cb);
	dma_fence_put(fence);
	return total;
}

/* Every queue's new PASS entries, a job an SDMA entity.  How many it took. */
static u32 knod_gda_pass_sdma(struct knod_gda *g)
{
	u32 total = 0, n;
	int ent;

	for (ent = 0; ent < g->pass_nent; ent++)
		while ((n = knod_gda_pass_job(g, ent)))
			total += n;
	return total;
}

static int knod_gda_rings_init(struct knod_gda *g)
{
	struct knod *knod = g->knod;
	struct knod_bpf_param *param;
	unsigned int pages, slots, r, k;
	struct knod_mem *mem;
	u64 *tbl;
	int i, n, err;

	g->slot_shift = knod_gda_slot_shift(g);
	g->htx_slots = KNOD_GDA_HTX_SLOTS >> (g->slot_shift - PAGE_SHIFT);
	if (g->slot_shift != PAGE_SHIFT)
		pr_info("knod: %s RX buffers of %u bytes for MTU %u\n",
			netdev_name(g->knodev->netdev), 1U << g->slot_shift,
			READ_ONCE(g->knodev->netdev->mtu));
	mem = knod_alloc_mem(knod,
			     roundup_pow_of_two(sizeof(struct knod_bpf_param)),
			     KFD_IOC_ALLOC_MEM_FLAGS_VRAM |
			     KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
			     KFD_IOC_ALLOC_MEM_FLAGS_COHERENT);
	if (IS_ERR_OR_NULL(mem))
		return -ENOMEM;
	param = mem->kaddr;
	memset_io((void __iomem *)param, 0, mem->size);
	writel(g->slot_shift, (void __iomem *)&param->page_shift);
	writeq(ktime_get_ns(), (void __iomem *)&param->ktime_ns);
	g->param = mem;

	/* The shader writes the PASS rings, the host reads them a packet at a
	 * time: in VRAM every one of those reads crosses the link uncached.
	 */
	mem = knod_alloc_mem(knod, knod_gda_pass_ring_off(g->nr_queues),
			     KFD_IOC_ALLOC_MEM_FLAGS_GTT |
			     KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
			     KFD_IOC_ALLOC_MEM_FLAGS_COHERENT);
	if (IS_ERR_OR_NULL(mem))
		return -ENOMEM;
	memset(mem->kaddr, 0, mem->size);
	g->pass_rings = mem;
	err = knod_gda_pass_init(g);
	if (err)
		return err;

	err = knod_gda_bind(g);
	if (err)
		return err;

	for (i = 0; i < g->nr_queues; i++) {
		pages = knod->buf[i]->size >> PAGE_SHIFT;
		r = g->slot_shift - PAGE_SHIFT;
		slots = pages >> r;
		tbl = kvmalloc_array(pages, sizeof(u64), GFP_KERNEL);
		if (!tbl)
			return -ENOMEM;
		/* What the engine's descriptors address each RX page by. */
		n = net_devmem_queue_data_addrs(g->binding, i, tbl, pages);
		if (n != pages) {
			pr_warn("knod: queue %d: %d of %u RX pages bound\n",
				i, n, pages);
			kvfree(tbl);
			return -EINVAL;
		}
		/* ...and each RX buffer by its first page's. */
		for (k = 0; k < slots; k++)
			tbl[k] = tbl[k << r];
		mem = knod_alloc_mem(knod, slots * sizeof(u64),
				     KFD_IOC_ALLOC_MEM_FLAGS_VRAM |
				     KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE);
		if (IS_ERR_OR_NULL(mem)) {
			kvfree(tbl);
			return -ENOMEM;
		}
		memcpy_toio((void __iomem *)mem->kaddr, tbl,
			    slots * sizeof(u64));
		kvfree(tbl);
		g->rx_dma[i] = mem;

		g->buf_mc[i] = kvmalloc_array(pages, sizeof(u64), GFP_KERNEL);
		if (!g->buf_mc[i])
			return -ENOMEM;
		err = knod_vram_mc_table(knod_gda_adev(g), knod->buf[i],
					 g->buf_mc[i], pages);
		if (err) {
			pr_warn("knod: queue %d: RX buffer not in VRAM: %d\n",
				i, err);
			return err;
		}
		g->htx_pc_mc[i] = knod_vram_mc(knod_gda_adev(g), g->control,
				offsetof(struct knod_persistent_mem, control.gda) +
				i * sizeof(struct knod_persistent_gda) +
				offsetof(struct knod_persistent_gda, htx_pc));
		if (!g->htx_pc_mc[i])
			return -EINVAL;

		mem = knod_alloc_mem(knod, KNOD_GDA_HTX_BYTES,
				     KFD_IOC_ALLOC_MEM_FLAGS_GTT |
				     KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
				     KFD_IOC_ALLOC_MEM_FLAGS_COHERENT);
		if (IS_ERR_OR_NULL(mem))
			return -ENOMEM;
		memset(mem->kaddr + KNOD_GDA_HTX_RING_OFF, 0,
		       mem->size - KNOD_GDA_HTX_RING_OFF);
		g->htx[i] = mem;
	}
	return 0;
}

static void knod_gda_rings_exit(struct knod_gda *g)
{
	int i;

	if (g->htx_task)
		kthread_stop(g->htx_task);
	g->htx_task = NULL;
	/* No SDMA job writes to the rings once they go. */
	knod_ksdma_entities_fini(g->htx_ent, g->htx_nent);
	while (g->htx_nent) {
		g->htx_nent--;
		if (g->htx_last[g->htx_nent])
			dma_fence_wait(g->htx_last[g->htx_nent], false);
		dma_fence_put(g->htx_last[g->htx_nent]);
		g->htx_last[g->htx_nent] = NULL;
	}
	for (i = 0; i < KNOD_SPSC_MAX; i++)
		skb_queue_purge(&g->htx_backlog[i]);

	/* The queues back to the NIC's own: rebuilt in its memory if up, and
	 * none of ours mapped for it any more.
	 */
	if (g->binding)
		net_devmem_unbind_queues(g->binding);
	g->binding = NULL;
	for (i = 0; i < KNOD_SPSC_MAX; i++) {
		if (g->rx_dma[i])
			knod_free_mem(g->knod, g->rx_dma[i]);
		g->rx_dma[i] = NULL;
		kvfree(g->buf_mc[i]);
		g->buf_mc[i] = NULL;
		if (g->htx[i])
			knod_free_mem(g->knod, g->htx[i]);
		g->htx[i] = NULL;
	}
	knod_gda_pass_unpublish(g);
	knod_gda_pass_exit(g);
	if (g->pass_rings)
		knod_free_mem(g->knod, g->pass_rings);
	g->pass_rings = NULL;
	if (g->param)
		knod_free_mem(g->knod, g->param);
	g->param = NULL;
}

static void knod_gda_unmap_doorbell(struct knod_gda *g, int i)
{
	if (g->db_mem[i])
		knod_free_mem(g->knod, g->db_mem[i]);
	g->db_mem[i] = NULL;
	g->db_gaddr[i] = 0;
	g->db_phys[i] = 0;
}

static void knod_gda_unmap_doorbells(struct knod_gda *g)
{
	int i;

	for (i = 0; i < KNOD_SPSC_MAX; i++)
		knod_gda_unmap_doorbell(g, i);
}

/*
 * Each queue's doorbell in the GPU's address space, so the shader can ring
 * it without the CPU: where the NIC said when it built the queue, on a page
 * of the queue's own.  At every shader start, since a rebuild may move it;
 * mapped again only if it did.  A queue with none keeps a zero entry, and
 * its XDP_TX drops.
 */
static void knod_gda_map_doorbells(struct knod_gda *g)
{
	struct knod_mem *mem;
	phys_addr_t phys;
	int i;

	for (i = 0; i < g->nr_queues; i++) {
		const struct net_dmq_info *info = &g->q[i].info;

		phys = 0;
		if (READ_ONCE(g->q[i].up) && info->nr_doorbells &&
		    info->doorbell[0].width == 8 &&
		    offset_in_page(info->doorbell[0].phys) <= PAGE_SIZE - 8)
			phys = info->doorbell[0].phys;
		if (phys == g->db_phys[i])
			continue;

		knod_gda_unmap_doorbell(g, i);
		if (!phys)
			continue;
		mem = knod_map_mmio(g->knod, phys & PAGE_MASK, PAGE_SIZE);
		if (IS_ERR(mem)) {
			pr_warn("knod: queue %d doorbell %pa not mappable: %ld\n",
				i, &phys, PTR_ERR(mem));
			continue;
		}
		g->db_mem[i] = mem;
		g->db_phys[i] = phys;
		g->db_gaddr[i] = mem->gaddr + offset_in_page(phys);
	}
}

/* As many offsets, up to eight, as leave the furthest frame in its page;
 * a power of two of them, so the shader masks.
 */
static void knod_gda_stagger_init(struct knod_gda *g,
				  struct knod_persistent_gda *e, u32 bounds)
{
	u32 stride = READ_ONCE(knod_gda_stagger), size = 1U << g->slot_shift;
	u32 frame = bounds >> 16, n;

	e->stagger = 0;
	e->stagger_mask = 0;
	if (!stride || !is_power_of_2(stride) || !frame || frame >= size)
		return;
	n = clamp_t(u32, (size - frame) / stride, 1, 8);
	e->stagger = stride;
	e->stagger_mask = rounddown_pow_of_two(n) - 1;
}

/* mlx5's entry, out of what the NIC said; the RX bounds back.  sq is the
 * SQ's offset in the ring buffer, zero for none.
 */
static u32 knod_gda_entry_mlx5(struct knod_gda *g,
			       struct knod_persistent_gda *e,
			       const struct net_dmq_info *info)
{
	const struct net_dmq_mlx5 *m = (const void *)info->fmt_priv;

	e->rq_log = ilog2(info->ring[NET_DMQ_MLX5_RQ].entries);
	e->rq_log_stride = ilog2(info->ring[NET_DMQ_MLX5_RQ].stride);
	e->cq_log = ilog2(info->ring[NET_DMQ_MLX5_RX_CQ].entries);
	e->frag = m->frag_size;
	e->headroom = m->headroom;
	e->mkey_be = (__force u32)cpu_to_be32(info->data_key);
	e->sqn = m->sqn;
	e->sq_mask = info->ring[NET_DMQ_MLX5_SQ].entries - 1;
	e->tx_mkey_be = e->mkey_be;
	e->tx_cq_log = ilog2(info->ring[NET_DMQ_MLX5_TX_CQ].entries);
	e->sq = m->sqn ? info->ring[NET_DMQ_MLX5_SQ].offset : 0;
	return knod_rx_bounds_encode(m->headroom, m->frame_size);
}

/* bnxt's: no keys, every ring's doorbell value instead, and an RQ with more
 * entries than are ever posted.  Its SQ id may be zero: it is the SQ's key.
 */
static u32 knod_gda_entry_bnxt(struct knod_gda *g,
			       struct knod_persistent_gda *e,
			       const struct net_dmq_info *info)
{
	const struct net_dmq_bnxt *b = (const void *)info->fmt_priv;
	int k;

	e->rq_log = ilog2(b->rq_posted);
	e->rq_ring_log = ilog2(info->ring[NET_DMQ_BNXT_RQ].entries);
	e->rq_log_stride = ilog2(info->ring[NET_DMQ_BNXT_RQ].stride);
	e->cq_log = ilog2(info->ring[NET_DMQ_BNXT_RX_CQ].entries);
	for (k = 0; k < NET_DMQ_BNXT_RINGS; k++)
		e->db_key[k] = b->db_key[k];
	e->frag = b->frag_size;
	e->headroom = b->headroom;
	e->mkey_be = 0;
	e->sqn = 0;
	e->sq_mask = info->ring[NET_DMQ_BNXT_SQ].entries - 1;
	e->tx_mkey_be = 0;
	e->tx_cq_log = ilog2(info->ring[NET_DMQ_BNXT_TX_CQ].entries);
	e->sq = info->ring[NET_DMQ_BNXT_SQ].offset;
	return knod_rx_bounds_encode(b->headroom, b->frame_size);
}

/* Host TX from the RX buffer's pages past the RQ's, as many as the SQ has
 * entries or more; none if there are not.
 */
static void knod_gda_htx_init(struct knod_gda *g, int i,
			      struct knod_persistent_gda *e)
{
	u32 pool = 1U << e->rq_log;
	u32 slots = g->knod->buf[i]->size >> g->slot_shift;
	u32 n = slots > pool ? rounddown_pow_of_two(slots - pool) : 0;

	e->htx = 0;
	WRITE_ONCE(g->htx_on[i], false);
	if (!e->sq || n < e->sq_mask + 1) {
		pr_info("knod: queue %d no host TX: %u spare RX buffers, %u SQ entries\n",
			i, n, e->sq ? e->sq_mask + 1 : 0);
		return;
	}
	e->htx_mask = g->htx_slots - 1;
	e->htx_pool = pool;
	e->htx_pool_mask = n - 1;
	e->htx = g->htx[i]->gaddr;
	g->htx_pool[i] = pool;
	g->htx_pool_mask[i] = n - 1;
	WRITE_ONCE(g->htx_on[i], true);
}

#define KNOD_HTX_BACKLOG	4096

struct knod_htx_cb {
	u64 meta;
	u64 queued;	/* debug: ktime ns */
};

#define KNOD_HTX_CB(skb)	((struct knod_htx_cb *)(skb)->cb)

/* A frame that did not make it to the GPU: dropped, never sent as it is. */
static void knod_gda_xmit_drop(struct sk_buff *skb)
{
	dev_core_stats_tx_dropped_inc(skb->dev);
	kfree_skb(skb);
}

/*
 * @skb to send on queue @q from the shader, its ring entry @meta besides
 * the length: taken, and left for the worker to move to the GPU.
 */
void knod_gda_xmit_skb(struct knod_gda *g, u32 q, struct sk_buff *skb,
		       u64 meta)
{
	if (q >= g->nr_queues || !g->htx_task || !READ_ONCE(g->htx_on[q]) ||
	    !READ_ONCE(g->q[q].up) ||
	    skb_queue_len(&g->htx_backlog[q]) >= KNOD_HTX_BACKLOG) {
		knod_gda_xmit_drop(skb);
		return;
	}
	KNOD_HTX_CB(skb)->meta = meta;
	KNOD_HTX_CB(skb)->queued = ktime_get_ns();
	skb_queue_tail(&g->htx_backlog[q], skb);
	wake_up_process(g->htx_task);
}

/* Frames a job takes, and pieces of them: a frame is a page or less.  The
 * producer moves every KNOD_HTX_SDMA_STEP of them, so the engine takes the
 * first while SDMA copies the rest.
 */
#define KNOD_HTX_SDMA_BATCH	256
#define KNOD_HTX_SDMA_STEP	64
#define KNOD_HTX_SDMA_SEGS	(4 * KNOD_HTX_SDMA_BATCH)

/*
 * Frames on their way by SDMA: held, mapped, until its fence.  Frame i's
 * pieces are seg[first[i]] up to seg[first[i + 1]].
 */
struct knod_htx_batch {
	struct dma_fence_cb cb;
	struct knod_gda *g;
	u64 submitted;	/* debug: ktime ns */
	struct dma_fence *fence;
	struct amdgpu_device *adev;
	u32 n, nseg;
	struct sk_buff *skb[KNOD_HTX_SDMA_BATCH];
	u16 first[KNOD_HTX_SDMA_BATCH + 1];
	struct {
		dma_addr_t dma;
		u32 len;
	} seg[KNOD_HTX_SDMA_SEGS];
};

static void knod_htx_batch_done(struct dma_fence *f, struct dma_fence_cb *cb)
{
	struct knod_htx_batch *b = container_of(cb, struct knod_htx_batch, cb);
	u64 now = ktime_get_ns();
	u32 i;

	if (f && b->g) {
		atomic64_add(now - b->submitted, &b->g->htx_sdma_ns);
		atomic64_inc(&b->g->htx_sdma_n);
	}
	for (i = 0; i < b->nseg; i++)
		knod_agp_unmap(b->adev, b->seg[i].dma, b->seg[i].len,
			       DMA_TO_DEVICE);
	for (i = 0; i < b->n; i++) {
		if (b->g && b->skb[i] == READ_ONCE(b->g->htx_probe))
			WRITE_ONCE(b->g->htx_probe_fence, now);
		dev_consume_skb_any(b->skb[i]);
	}
	dma_fence_put(b->fence);
	kvfree(b);
}

/*
 * Up to a batch of queue @q's waiting frames, as far as its ring has slots:
 * each skb's pieces copied by the kernel's SDMA into the frame's pool page,
 * its ring entry marked in place, and the entry's producer moved by SDMA
 * once they are all there.  False when nothing more can go now.
 */
/*
 * @len bytes from @src to an RX buffer at @off, its pages' addresses @mc:
 * a copy each run of them contiguous in VRAM.
 */
static void knod_gda_htx_copy(struct knod_ksdma_batch *sb, const u64 *mc,
			      u32 off, u64 src, u32 len)
{
	u32 end = off + len, first, p, run;

	while (off < end) {
		first = off >> PAGE_SHIFT;
		for (p = first; (p + 1) << PAGE_SHIFT < end &&
		     mc[p + 1] == mc[p] + PAGE_SIZE; p++)
			;
		run = min(end, (p + 1) << PAGE_SHIFT) - off;
		knod_ksdma_copy(sb, src, mc[first] + offset_in_page(off), run);
		src += run;
		off += run;
	}
}

static bool knod_gda_htx_sdma(struct knod_gda *g, int q)
{
	struct amdgpu_device *adev = knod_gda_adev(g);
	void *htx = g->htx[q]->kaddr;
	u32 *pc = htx + knod_gda_htx_ctl_off(g) + KNOD_PERSIST_HTX_PC;
	u32 *cc = htx + knod_gda_htx_ctl_off(g) + KNOD_PERSIST_HTX_CC;
	u32 r = g->slot_shift - PAGE_SHIFT, size = 1U << g->slot_shift;
	u64 *ring = htx + KNOD_GDA_HTX_RING_OFF;
	struct knod_ksdma_batch sb;
	struct knod_htx_batch *b;
	u32 room, i, j, k, off, page;
	struct knod_skb_map m;
	struct sk_buff *skb;

	room = g->htx_slots - (*pc - READ_ONCE(*cc));
	if (!room || skb_queue_empty(&g->htx_backlog[q]))
		return false;
	b = kvmalloc_obj(*b, GFP_KERNEL);
	if (!b)
		return false;
	b->adev = adev;
	b->g = g;
	b->n = 0;
	b->nseg = 0;
	while (b->n < min_t(u32, room, KNOD_HTX_SDMA_BATCH) &&
	       (skb = skb_dequeue(&g->htx_backlog[q]))) {
		if (skb->len > size || knod_agp_map_skb(adev, skb, &m)) {
			knod_gda_xmit_drop(skb);
			continue;
		}
		/* No room for its pieces: the next job takes it. */
		if (b->nseg + m.n > KNOD_HTX_SDMA_SEGS) {
			knod_agp_unmap_skb(adev, &m);
			skb_queue_head(&g->htx_backlog[q], skb);
			break;
		}
		b->first[b->n] = b->nseg;
		for (j = 0; j < m.n; j++) {
			b->seg[b->nseg + j].dma = m.seg[j].dma;
			b->seg[b->nseg + j].len = m.seg[j].len;
		}
		b->nseg += m.n;
		b->skb[b->n++] = skb;
	}
	b->first[b->n] = b->nseg;
	/* A piece splits where the RX buffer's pages do not run on in VRAM:
	 * at most once a page past a frame's first.
	 */
	if (!b->n || knod_ksdma_begin(&sb, adev, &g->htx_ent[q % g->htx_nent],
				      b->nseg + b->n * ((1U << r) - 1),
				      DIV_ROUND_UP(b->n, KNOD_HTX_SDMA_STEP))) {
		knod_htx_batch_done(NULL, &b->cb);
		return false;
	}

	for (i = 0; i < b->n; i++) {
		k = *pc + i;
		page = g->htx_pool[q] + (k & g->htx_pool_mask[q]);
		for (j = b->first[i], off = 0; j < b->first[i + 1]; j++) {
			knod_gda_htx_copy(&sb, g->buf_mc[q] + ((size_t)page << r),
					  off, knod_agp_addr(adev, b->seg[j].dma,
							     b->seg[j].len),
					  b->seg[j].len);
			off += b->seg[j].len;
		}
		ring[k & (g->htx_slots - 1)] = b->skb[i]->len |
			KNOD_HTX_CB(b->skb[i])->meta | KNOD_PERSIST_HTX_INPLACE;
		if ((i + 1) % KNOD_HTX_SDMA_STEP == 0 || i + 1 == b->n)
			knod_ksdma_write32(&sb, g->htx_pc_mc[q], k + 1);
	}
	*pc += b->n;
	/* The entries before the job that makes the shader look at them. */
	wmb();
	b->submitted = ktime_get_ns();
	for (i = 0; i < b->n; i++) {
		atomic64_add(b->submitted - KNOD_HTX_CB(b->skb[i])->queued,
			     &g->htx_wait_ns);
		if (b->skb[i] == READ_ONCE(g->htx_probe))
			WRITE_ONCE(g->htx_probe_submit, b->submitted);
	}
	atomic64_add(b->n, &g->htx_wait_n);
	b->fence = knod_ksdma_submit(&sb);
	dma_fence_put(g->htx_last[q % g->htx_nent]);
	g->htx_last[q % g->htx_nent] = dma_fence_get(b->fence);
	if (dma_fence_add_callback(b->fence, &b->cb, knod_htx_batch_done))
		knod_htx_batch_done(b->fence, &b->cb);
	return true;
}

/* An SDMA entity of our own on each of the kernel's SDMA rings. */
static int knod_gda_htx_entities(struct knod_gda *g)
{
	int n = knod_ksdma_entities_init(knod_gda_adev(g), g->htx_ent,
					 KNOD_HTX_SDMA_RINGS);

	if (n < 0)
		return n;
	g->htx_nent = n;
	return 0;
}

/* Whether any queue has frames waiting for the worker. */
static bool knod_gda_htx_waiting(struct knod_gda *g)
{
	int q;

	for (q = 0; q < g->nr_queues; q++)
		if (!skb_queue_empty(&g->htx_backlog[q]))
			return true;
	return false;
}

#define KNOD_HTX_SPIN_NS	(50 * NSEC_PER_USEC)

/*
 * The worker, a thread of its own: every queue's waiting frames to the GPU
 * until none wait, then a short spin for more before it sleeps - frames
 * that come one at a time, ACKs, would otherwise wait for it to wake.  A
 * queue whose ring is full waits for the shader to take some.
 */
static int knod_gda_htx_thread(void *data)
{
	struct knod_gda *g = data;
	bool moved, waiting;
	u64 until;
	int q;

	while (!kthread_should_stop()) {
		moved = false;
		waiting = false;
		for (q = 0; q < g->nr_queues; q++) {
			if (!READ_ONCE(g->htx_on[q]) || !READ_ONCE(g->q[q].up)) {
				skb_queue_purge(&g->htx_backlog[q]);
				continue;
			}
			while (knod_gda_htx_sdma(g, q))
				moved = true;
			waiting |= !skb_queue_empty(&g->htx_backlog[q]);
		}
		if (waiting) {
			if (!moved)
				usleep_range(10, 20);
			continue;
		}
		until = ktime_get_ns() + KNOD_HTX_SPIN_NS;
		while (!knod_gda_htx_waiting(g) && ktime_get_ns() < until &&
		       !kthread_should_stop())
			cpu_relax();
		set_current_state(TASK_INTERRUPTIBLE);
		if (!knod_gda_htx_waiting(g) && !kthread_should_stop())
			schedule();
		__set_current_state(TASK_RUNNING);
	}
	return 0;
}

/* What the shader reads for each queue whose rings the NIC gave us. */
static void knod_gda_rings_control(struct knod_gda *g,
				   struct knod_persistent_mem *mem)
{
	struct knod_bpf_param *param = g->param->kaddr;
	struct knod *knod = g->knod;
	struct knod_persistent_gda entry, *e = &entry;
	void __iomem *dst;
	u32 bounds;
	int i;

	for (i = 0; i < g->nr_queues; i++) {
		const struct net_dmq_info *info = &g->q[i].info;

		dst = (void __iomem *)&mem->control.gda[i];
		memcpy_fromio(e, dst, sizeof(*e));
		e->live = 0;
		if (!READ_ONCE(g->q[i].up)) {
			pr_info("knod: queue %d receive rings not ours\n", i);
			WRITE_ONCE(g->htx_on[i], false);
			writel(0, (void __iomem *)&mem->control.gda[i].live);
			continue;
		}
		smp_rmb();	/* pairs with knod_gda_queue_up() */
		if (!knod_gda_queue_ok(g, i)) {
			pr_warn("knod: queue %d rings are not where the engine reads them\n",
				i);
			WRITE_ONCE(g->htx_on[i], false);
			writel(0, (void __iomem *)&mem->control.gda[i].live);
			continue;
		}
		e->ring = knod->gda_rx[i]->gaddr;
		e->rx_dma = g->rx_dma[i]->gaddr;
		e->gen = info->gen;
		if (knod_gda_fmt_bnxt(g->fmt))
			bounds = knod_gda_entry_bnxt(g, e, info);
		else
			bounds = knod_gda_entry_mlx5(g, e, info);
		/* The MTU raised since the buffers were laid out. */
		if ((bounds >> 16) > 1U << g->slot_shift) {
			pr_warn("knod: queue %d frames of %u bytes past RX buffers of %u: attach again\n",
				i, bounds >> 16, 1U << g->slot_shift);
			WRITE_ONCE(g->htx_on[i], false);
			writel(0, (void __iomem *)&mem->control.gda[i].live);
			continue;
		}
		knod_gda_stagger_init(g, e, bounds);
		/* pass_pc carries over, as ci does: what the host is still
		 * to deliver was copied out already.
		 */
		e->pass_ring = g->pass_rings->gaddr + knod_gda_pass_ring_off(i);
		e->pass_stage = g->pass_stage[i]->gaddr;
		e->pass_mask = g->pass_slots - 1;
		knod_gda_pass_publish(g, i);
		e->rx_base = knod->buf[i]->gaddr;
		/* The SQ rings at the doorbell: without one, XDP_TX drops. */
		e->tx_gen = info->gen;
		if (e->sq && g->db_gaddr[i]) {
			e->sq += knod->gda_rx[i]->gaddr;
		} else {
			pr_info("knod: queue %d XDP SQ not ours (sqn %u db %llx), XDP_TX drops\n",
				i, e->sqn, g->db_gaddr[i]);
			e->sq = 0;
		}
		knod_gda_htx_init(g, i, e);
		/* ci, posted_gen and pause_ack are the shader's; a ring of a
		 * new generation is how it knows to drop them.
		 */
		e->live = 1;
		writel(bounds, (void __iomem *)&param->queues[i].rx_bounds);
		/* Preserve shader-owned state. */
		memcpy_toio(dst, e, offsetof(struct knod_persistent_gda, packets));
		memcpy_toio(dst + offsetof(struct knod_persistent_gda, rq_log),
			    &e->rq_log, offsetof(struct knod_persistent_gda, ci) -
			    offsetof(struct knod_persistent_gda, rq_log));
		memcpy_toio(dst + offsetof(struct knod_persistent_gda, sq),
			    &e->sq, offsetof(struct knod_persistent_gda, tx_packets) -
			    offsetof(struct knod_persistent_gda, sq));
		memcpy_toio(dst + offsetof(struct knod_persistent_gda, stagger),
			    &e->stagger, offsetof(struct knod_persistent_gda, pass_pc) -
			    offsetof(struct knod_persistent_gda, stagger));
		memcpy_toio(dst + offsetof(struct knod_persistent_gda, htx),
			    &e->htx, offsetof(struct knod_persistent_gda, htx_pc) -
			    offsetof(struct knod_persistent_gda, htx));
	}
	writeq(g->param->gaddr, (void __iomem *)&mem->control.gda_param);
	writel(g->lds_bytes, (void __iomem *)&mem->control.gda_lds);
	writel(g->waves, (void __iomem *)&mem->control.gda_waves);
	writeq(g->ipsec_sa, (void __iomem *)&mem->control.ipsec_sa);
	writeq(g->ipsec_ttab, (void __iomem *)&mem->control.ipsec_ttab);
	writel(g->ipsec_sa_mask, (void __iomem *)&mem->control.ipsec_sa_mask);
}

static void knod_gda_control_init(struct knod_gda *g)
{
	struct knod_persistent_mem *mem = knod_gda_mem(g);
	struct amd_signal terminal;
	int i;

	WARN_ON_ONCE(g->running);
	/* Everything but the rings' state: the rings carried on while no
	 * shader ran, and the next one picks up where the last left them.
	 */
	memset_io((void __iomem *)mem, 0,
		  offsetof(struct knod_persistent_mem, control.gda));
	memset_io((void __iomem *)mem +
		  offsetofend(struct knod_persistent_mem, control.gda),
	       0, sizeof(*mem) -
	       offsetofend(struct knod_persistent_mem, control.gda));
	for (i = 0; i < g->nr_queues; i++)
		writeq(g->db_gaddr[i], (void __iomem *)&mem->control.tx_db[i]);
	knod_gda_rings_control(g, mem);
	writel(KNOD_PERSIST_VERSION, (void __iomem *)&mem->control.version);
	terminal = *(struct amd_signal *)g->knod->kaql[0].queue_signal->kaddr;
	terminal.value = 1;
	memcpy_toio((void __iomem *)&mem->terminal, &terminal, sizeof(terminal));
	/* Publish CPU BAR writes before the shader consumes them. */
	wmb();
	amdgpu_device_flush_hdp(knod_gda_adev(g), NULL);
}

/* Code into the slot, where the stopped shader's next launch finds it: the
 * engine at the entry, and the program right after it, which the engine's
 * call is pointed at.
 */
static void knod_gda_copy_code(struct knod_gda *g)
{
	struct knod_mem *slot = g->knod->kernel;
	u8 *entry = slot->kaddr + KNOD_GDA_ENTRY_OFFSET;
	u32 end = g->engine.size + g->code_size;
	u32 call;

	memcpy(entry, g->engine.code, g->engine.size);
	/* s_getpc gives the address of the add the offset is part of. */
	call = g->engine.size - (g->engine.call - 4);
	memcpy(entry + g->engine.call, &call, sizeof(call));
	memcpy(entry + g->engine.size, g->code, g->code_size);
	memset(entry + end, 0, slot->size - KNOD_GDA_ENTRY_OFFSET - end);
	/*
	 * The slot is write-combining VRAM: drain the WC buffers before the
	 * shader is launched on it, or it may fetch half-written code.
	 */
	wmb();
}

/*
 * Park every queue at its next round boundary - the code finished, its stores
 * out - and wait until each has.  Only a program touches what the host
 * changes: the receive kernel is left to run.
 */
int knod_gda_park(struct knod *knod)
{
	struct knod_gda *g = knod->gda;
	struct knod_persistent_mem *mem;
	unsigned long deadline;
	u32 value;
	bool parked;
	int i;

	if (g->code_is_default || !g->running)
		return 0;

	mem = knod_gda_mem(g);
	/* Never one a queue has acked before, so an old ack is no answer. */
	value = ++g->park_seq ?: ++g->park_seq;
	g->park_value = value;
	writel(value, (void __iomem *)&mem->control.pause);
	/* Publish CPU BAR writes before the shader consumes them. */
	wmb();
	amdgpu_device_flush_hdp(knod_gda_adev(g), NULL);
	deadline = jiffies + msecs_to_jiffies(1000);
	do {
		parked = true;
		for (i = 0; i < g->nr_queues; i++)
			if (readl((void __iomem *)&mem->control.gda[i].live) &&
			    readl((void __iomem *)&mem->control.gda[i].pause_ack) != value)
				parked = false;
		if (parked) {
			/* What the parked waves wrote, before the host reads. */
			dma_rmb();
			return 0;
		}
		usleep_range(20, 50);
	} while (time_before(jiffies, deadline));

	pr_warn("knod: queues did not park\n");
	writel(0, (void __iomem *)&mem->control.pause);
	/* Publish CPU BAR writes before the shader consumes them. */
	wmb();
	amdgpu_device_flush_hdp(knod_gda_adev(g), NULL);
	g->park_value = 0;
	return -ETIMEDOUT;
}
EXPORT_SYMBOL(knod_gda_park);

void knod_gda_unpark(struct knod *knod)
{
	struct knod_gda *g = knod->gda;

	if (!g->park_value)
		return;
	/* The host's writes land before the queues run again: out of the CPU's
	 * write buffers, and out of the HDP for what went to VRAM.
	 */
	/* Publish CPU BAR writes before the shader consumes them. */
	wmb();
	amdgpu_device_flush_hdp(knod->process->pdds[0]->dev->adev, NULL);
	writel(0, (void __iomem *)&knod_gda_mem(g)->control.pause);
	/* Publish CPU BAR writes before the shader consumes them. */
	wmb();
	amdgpu_device_flush_hdp(knod_gda_adev(g), NULL);
	g->park_value = 0;
}
EXPORT_SYMBOL(knod_gda_unpark);

bool knod_gda_op_trylock(struct knod *knod)
{
	struct knod_gda *g = knod->gda;

	return !READ_ONCE(g->pause_requested) && mutex_trylock(&g->op_lock);
}
EXPORT_SYMBOL(knod_gda_op_trylock);

void knod_gda_op_unlock(struct knod *knod)
{
	mutex_unlock(&knod->gda->op_lock);
}
EXPORT_SYMBOL(knod_gda_op_unlock);

/*
 * Stop the worker restarting the shader, and for anything but a program
 * change park the queues, with op_lock held on success until resume.
 */
int knod_gda_pause(struct knod *knod, enum knod_gda_pause_reason reason)
{
	struct knod_gda *g = knod->gda;
	u64 request;

	mutex_lock(&g->op_lock);

	/* Still paused from a caller that failed. */
	if (READ_ONCE(g->pause_requested) &&
	    /* Pairs with the worker's release of its ack. */
	    smp_load_acquire(&g->pause_ack) == READ_ONCE(g->pause_request))
		return 0;

	request = g->pause_request + 1;
	g->pause_requests++;
	g->pause_reasons[reason]++;
	WRITE_ONCE(g->pause_requested, true);
	/* The request after the flag; pairs with the worker's acquire. */
	smp_store_release(&g->pause_request, request);
	knod_gda_wake_worker(g);
	if (!READ_ONCE(g->worker)) {
		/* No worker to restart the shader: ack for it. */
		smp_store_release(&g->pause_ack, request);
		g->pause_acks++;
		return 0;
	}

	wait_event(g->op_wq,
		   /* Pairs with the worker's release of its ack. */
		   smp_load_acquire(&g->pause_ack) == request ||
		   !READ_ONCE(g->worker));
	if (smp_load_acquire(&g->pause_ack) != request) {	/* as above */
		mutex_unlock(&g->op_lock);
		return -ESHUTDOWN;
	}
	if (reason != KNOD_GDA_PAUSE_PROGRAM && knod_gda_park(knod)) {
		/* Not paused: nothing held, and nothing for the next caller
		 * to take as a pause still in force.
		 */
		/* Pairs with the worker's acquire of the flag. */
		smp_store_release(&g->pause_requested, false);
		knod_gda_wake_worker(g);
		wake_up(&g->op_wq);
		mutex_unlock(&g->op_lock);
		return -ETIMEDOUT;
	}
	return 0;
}
EXPORT_SYMBOL(knod_gda_pause);

void knod_gda_resume(struct knod *knod)
{
	struct knod_gda *g = knod->gda;

	knod_gda_unpark(knod);
	/* The host's writes before the worker may restart the shader. */
	smp_store_release(&g->pause_requested, false);
	knod_gda_wake_worker(g);
	wake_up(&g->op_wq);
	mutex_unlock(&g->op_lock);
}
EXPORT_SYMBOL(knod_gda_resume);

/* A pause the caller could not finish: it stays in force. */
void knod_gda_leave_paused(struct knod *knod)
{
	mutex_unlock(&knod->gda->op_lock);
}
EXPORT_SYMBOL(knod_gda_leave_paused);

/*
 * Put @code, @size bytes wanting @lds_bytes of LDS for its stack, in the
 * shader's place, behind @engine or, NULL, the core's: stop the shader, copy,
 * and leave the worker to start it again.  The engine keeps pointers to
 * @code and @engine's code, which have to stay until the next install.
 */
int knod_gda_install(struct knod *knod, const void *code, u32 size,
		     u32 lds_bytes, bool needs_clock,
		     const struct knod_gda_engine *engine)
{
	struct knod_gda *g = knod->gda;
	int err;

	if (!engine)
		engine = &g->core_engine;
	if (!code || !size ||
	    size > knod->kernel->size - KNOD_GDA_ENTRY_OFFSET - engine->size ||
	    lds_bytes + engine->lds_bytes > knod->lds_size)
		return -E2BIG;

	err = knod_gda_pause(knod, KNOD_GDA_PAUSE_PROGRAM);
	if (err)
		return err;
	knod_gda_shader_stop(g, KNOD_GDA_STOP_PROGRAM);
	g->engine = *engine;
	g->code = code;
	g->code_size = size;
	g->lds_bytes = lds_bytes;
	WRITE_ONCE(g->needs_clock, needs_clock);
	g->code_is_default = false;
	knod_gda_copy_code(g);
	WRITE_ONCE(g->kernel_fault, false);
	pr_debug("knod: install %u bytes\n", size);
	knod_gda_resume(knod);
	return 0;
}
EXPORT_SYMBOL(knod_gda_install);

static const void *knod_gda_default_code(struct knod *knod, u32 *size)
{
	return knod_blob_find(&knod->core_blob, KNOD_BLOB_GDA_RX_KERNEL, 0,
			      size);
}

/* Back to the receive kernel, which passes everything. */
int knod_gda_install_default(struct knod *knod)
{
	const void *code;
	u32 size;
	int err;

	code = knod_gda_default_code(knod, &size);
	if (!code)
		return -ENOENT;
	err = knod_gda_install(knod, code, size, 0, false, NULL);
	if (!err)
		knod->gda->code_is_default = true;
	return err;
}
EXPORT_SYMBOL(knod_gda_install_default);

/* What is in the slot may be a program already let go of: run nothing until
 * an install goes in whole.
 */
void knod_gda_mark_fault(struct knod *knod)
{
	WRITE_ONCE(knod->gda->kernel_fault, true);
	knod_gda_wake_worker(knod->gda);
}
EXPORT_SYMBOL(knod_gda_mark_fault);

void knod_gda_set_client(struct knod *knod,
			 const struct knod_gda_client *client, void *ctx)
{
	struct knod_gda *g = knod->gda;

	/* No tick of the last client is running once this returns. */
	mutex_lock(&g->client_lock);
	g->client = client;
	g->client_ctx = ctx;
	mutex_unlock(&g->client_lock);
	knod_gda_wake_worker(g);
}
EXPORT_SYMBOL(knod_gda_set_client);

/* PASS entries appended since the last kick. */
static bool knod_gda_pass_pending(struct knod_gda *g)
{
	int i;

	for (i = 0; i < g->nr_queues; i++)
		if (knod_gda_pass_pc(g, i) != g->pass_seen[i])
			return true;
	return false;
}

/*
 * Nothing to take: ask the shader to interrupt when it next appends PASS
 * entries, look once more for any it appended before it saw the ask, and
 * sleep until the interrupt or until the rest of the loop is due.
 */
static void knod_gda_pass_wait(struct knod_gda *g, unsigned int events)
{
	struct knod_persistent_mem *mem = knod_gda_mem(g);
	s64 timeout = READ_ONCE(g->needs_clock) ?
		150 * NSEC_PER_USEC : 100 * NSEC_PER_MSEC;

	if (!g->pass_wait_armed) {
		WRITE_ONCE(g->pass_irq, false);
		writel(1, (void __iomem *)&mem->control.pass_wake);
		/* Publish the interrupt request before checking for pending PASS. */
		wmb();
		amdgpu_device_flush_hdp(knod_gda_adev(g), NULL);
		g->pass_wait_armed = true;
		/* The shader appends before reading the interrupt request. */
		mb();
		if (knod_gda_pass_pending(g)) {
			g->pass_wait_armed = false;
			return;
		}
	}
	wait_event_interruptible_hrtimeout(g->pass_wq,
					   READ_ONCE(g->pass_irq) ||
					   kthread_should_stop() ||
					   atomic_read(&g->worker_events) != events,
					   ns_to_ktime(timeout));
}

/* A shader appended PASS entries while the worker slept (KFD interrupt). */
bool knod_gda_irq(struct kfd_process *p, u32 partial_id)
{
	struct knod_gda *g;

	if (partial_id != KNOD_PERSIST_PASS_IRQ)
		return false;
	rcu_read_lock();
	g = rcu_dereference(p->knod_gda);
	if (g) {
		WRITE_ONCE(g->pass_irq, true);
		wake_up(&g->pass_wq);
	}
	rcu_read_unlock();
	return g;
}

static int knod_gda_worker(void *arg)
{
	struct knod_gda *g = arg;
	unsigned int events;
	u64 request;
	bool pause;

	while (!kthread_should_stop()) {
		events = atomic_read(&g->worker_events);
		mutex_lock(&g->client_lock);
		if (g->client && g->client->tick)
			g->client->tick(g->client_ctx);
		mutex_unlock(&g->client_lock);

		/* A timeout alone need not read or re-arm device memory. */
		if (!READ_ONCE(g->needs_clock) && g->pass_wait_armed &&
		    !READ_ONCE(g->pass_irq) && events == g->worker_seen_events &&
		    time_before(jiffies, g->pass_poll_at))
			goto wait;
		g->worker_seen_events = events;
		g->pass_poll_at = jiffies + HZ;
		g->pass_wait_armed = false;

		/* The program's clock: no packet carries one here. */
		if (READ_ONCE(g->needs_clock)) {
			writeq(ktime_get_ns(), (void __iomem *)g->param->kaddr +
			       offsetof(struct knod_bpf_param, ktime_ns));
			/* Publish the clock update before the shader reads it. */
			wmb();
			amdgpu_device_flush_hdp(knod_gda_adev(g), NULL);
		}

		/* Acquire a pause request and its generation. */
		pause = smp_load_acquire(&g->pause_requested);
		/* Pairs with the pauser's release of the request. */
		request = pause ? smp_load_acquire(&g->pause_request) : 0;
		if (READ_ONCE(g->kernel_fault)) {
			knod_gda_shader_stop(g, KNOD_GDA_STOP_PROGRAM);
		} else if (!pause && !g->running) {
			knod_gda_map_doorbells(g);
			knod_gda_control_init(g);
			knod_gda_shader_start(g);
		}

		/* Nothing the host could wait on is in flight here: the queues
		 * park themselves (knod_gda_park()), so a pause is
		 * acknowledged as soon as it is seen.
		 */
		if (pause &&
		    /* Pairs with a repeat request's acquire. */
		    smp_load_acquire(&g->pause_ack) != request) {
			g->pause_acks++;
			/* Pairs with the pauser's acquire. */
			smp_store_release(&g->pause_ack, request);
			wake_up(&g->op_wq);
		}

		/* The shader put PASS packets in staging: SDMA copies them
		 * to the stack's pages, and their queues' NAPIs deliver them.
		 */
		if (knod_gda_pass_sdma(g)) {
			cond_resched();
		} else if (knod_gda_pass_pending(g)) {
			/* Entries no page or job could be had for yet: the
			 * drain, or a job still out, frees some soon.
			 */
			usleep_range(10, 20);
		} else {
wait:
			knod_gda_pass_wait(g, events);
		}
	}
	return 0;
}

static void knod_gda_stop_worker(struct knod_gda *g)
{
	struct task_struct *task;

	task = xchg(&g->worker, NULL);
	if (task) {
		wake_up_all(&g->op_wq);
		knod_gda_wake_worker(g);
		kthread_stop(task);
		put_task_struct(task);
	}
	synchronize_net();
}

/* Interface up: the code into the slot, the shader on the rings the NIC just
 * built, and the worker that keeps it there.
 */
void knod_gda_start(struct knod *knod)
{
	struct knod_gda *g = knod->gda;
	struct task_struct *p;

	/* Not while code or maps are being changed: the control block this
	 * clears is what holds the queues parked for that.
	 */
	mutex_lock(&g->op_lock);
	knod_gda_stop_worker(g);
	knod_gda_shader_stop(g, KNOD_GDA_STOP_SHUTDOWN);
	pr_info("knod: %d queues, %u waves each\n", g->nr_queues, g->waves);

	if (knod_gda_hdp_cache_disable(g)) {
		pr_err("knod: cannot disable HDP read cache for VRAM TX SQ\n");
		mutex_unlock(&g->op_lock);
		return;
	}
	knod_gda_copy_code(g);
	knod_gda_map_doorbells(g);
	knod_gda_control_init(g);
	knod_gda_shader_start(g);

	p = kthread_run(knod_gda_worker, g, "knod_%d_0", knod->accel->id);
	if (IS_ERR(p)) {
		pr_err("knod: no worker: %ld\n", PTR_ERR(p));
		knod_gda_shader_stop(g, KNOD_GDA_STOP_SHUTDOWN);
		knod_gda_hdp_cache_restore(g);
	} else {
		get_task_struct(p);
		WRITE_ONCE(g->worker, p);
	}
	mutex_unlock(&g->op_lock);
}

/* Interface down: the shader leaves the rings where they stand, for the
 * next one to pick up.
 */
void knod_gda_stop(struct knod *knod)
{
	struct knod_gda *g = knod->gda;

	mutex_lock(&g->op_lock);
	knod_gda_stop_worker(g);
	knod_gda_shader_stop(g, KNOD_GDA_STOP_SHUTDOWN);
	knod_gda_hdp_cache_restore(g);
	mutex_unlock(&g->op_lock);
}

/*
 * The interface up or down: the engine on the NIC's rings once they are all
 * there - now, or when the NIC has built them (knod_gda_queue_up()) - or off
 * them until it is up again.
 */
void knod_gda_run(struct knod *knod, bool on)
{
	struct knod_gda *g = knod->gda;

	WRITE_ONCE(g->want, on);
	if (!on) {
		cancel_work_sync(&g->restart);
		knod_gda_stop(knod);
	} else if (READ_ONCE(g->ready) && knod_gda_all_up(g)) {
		knod_gda_start(knod);
	}
}

static const char *knod_gda_fmt_name(u32 fmt)
{
	switch (fmt) {
	case NET_DMQ_FMT_MLX5_CX5:
		return "mlx5_cx5";
	case NET_DMQ_FMT_BNXT_P5:
		return "bnxt_p5";
	case NET_DMQ_FMT_BNXT_P7:
		return "bnxt_p7";
	default:
		return "none";
	}
}

#define KNOD_GDA_RD32(e, f)	readl((void __iomem *)&(e)->f)
#define KNOD_GDA_RD64(e, f)	readq((void __iomem *)&(e)->f)

/* The completion the shader waits on next, as the NIC left it in accel
 * memory, and the owner or valid bit that would make it the shader's: one
 * the NIC never wrote, or wrote on a pass the shader is not on, is where a
 * queue that takes nothing stands.
 */
static void knod_gda_stats_next(struct seq_file *s, struct knod_gda *g,
				struct knod_persistent_gda *e, int q)
{
	const u8 *ring = g->knod->gda_rx[q]->kaddr;
	u32 ci = KNOD_GDA_RD32(e, ci), log = KNOD_GDA_RD32(e, cq_log);
	u32 mask = (1U << log) - 1, w0, w1, v0, v1, at;
	const u8 *c;

	if (!ring || log > 16)
		return;
	ring += KNOD_GDA_CQ_OFF;
	switch (g->fmt) {
	case NET_DMQ_FMT_MLX5_CX5:
		c = ring + (ci & mask) * 64;
		seq_printf(s, "q%-2d next cqe %u: op 0x%x owner %u (shader's: %u) wqe %u bytes %u\n",
			   q, ci & mask, READ_ONCE(c[63]) >> 4, READ_ONCE(c[63]) & 1,
			   (ci >> log) & 1,
			   be16_to_cpu(READ_ONCE(*(const __be16 *)(c + 60))),
			   be32_to_cpu(READ_ONCE(*(const __be32 *)(c + 44))));
		break;
	case NET_DMQ_FMT_BNXT_P5:
	case NET_DMQ_FMT_BNXT_P7:
		/* Two entries a completion, each with a valid bit set on the
		 * ring's even passes.
		 */
		at = 2 * ci;
		c = ring + (at & mask) * 16;
		w0 = le32_to_cpu(READ_ONCE(*(const __le32 *)c));
		w1 = le32_to_cpu(READ_ONCE(*(const __le32 *)(c + 4)));
		v0 = le32_to_cpu(READ_ONCE(*(const __le32 *)(c + 8))) & 1;
		v1 = le32_to_cpu(READ_ONCE(*(const __le32 *)(c + 24))) & 1;
		seq_printf(s, "q%-2d next cmp %u: type %u valid %u/%u (shader's: %u) len %u opaque %u\n",
			   q, at & mask, w0 & 0x3f, v0, v1, !((at >> log) & 1),
			   w0 >> 16, w1);
		break;
	}
}

/* Where a queue's rings are and how big, and where they stand. */
static void knod_gda_stats_queue(struct seq_file *s, struct knod_gda *g,
				 struct knod_persistent_gda *e, int q)
{
	const u8 *ring = g->knod->gda_rx[q]->kaddr;
	u32 fmt = g->fmt, ci = KNOD_GDA_RD32(e, ci);
	u32 rq_log = KNOD_GDA_RD32(e, rq_log), bounds, k;
	bool bnxt = knod_gda_fmt_bnxt(fmt);
	u64 key[KNOD_PERSIST_DB_KEYS];

	/* What the shader last gave back: the RQ producer is the oldest entry
	 * it holds plus the RQ's size, and the CQ consumer its ci - in
	 * entries, two a completion on bnxt.
	 */
	seq_printf(s, "q%-2d live %u rounds %llu packets %llu ci %u gen %u/%u rq_prod %u cq_cons %u pass %u/%u\n",
		   q, KNOD_GDA_RD32(e, live), KNOD_GDA_RD64(e, rounds),
		   KNOD_GDA_RD64(e, packets), ci, KNOD_GDA_RD32(e, posted_gen),
		   KNOD_GDA_RD32(e, gen),
		   KNOD_GDA_RD32(e, rq_bound) + (1U << rq_log),
		   bnxt ? 2 * ci : ci,
		   KNOD_GDA_RD32(e, pass_pc), knod_gda_pass_cc(g, q));
	/* Where each PASS packet waits: in staging for the worker, in an
	 * SDMA job, for the NIC's drain.
	 */
	if (g->pass_buf[q])
		seq_printf(s, "    pass staged %u copying %u to drain %u\n",
			   KNOD_GDA_RD32(e, pass_pc) - g->pass_seen[q],
			   g->pass_seen[q] - knod_gda_pass_cc(g, q),
			   READ_ONCE(g->knodev->wpriv[q].pass_pc) -
			   READ_ONCE(g->knodev->wpriv[q].pass_cc));
	/* mlx5 keeps the doorbell records in the ring buffer, as the NIC
	 * reads them: more RQ entries posted than CQ entries consumed plus
	 * the CQ's size is an overrun.
	 */
	if (ring && fmt == NET_DMQ_FMT_MLX5_CX5)
		seq_printf(s, "q%-2d records rq %u cq %u sq %u tx_cq %u\n", q,
			   be32_to_cpu(READ_ONCE(*(const __be32 *)
				(ring + KNOD_GDA_DB_OFF + KNOD_GDA_RQ_DB))),
			   be32_to_cpu(READ_ONCE(*(const __be32 *)
				(ring + KNOD_GDA_DB_OFF + KNOD_GDA_CQ_DB))),
			   be32_to_cpu(READ_ONCE(*(const __be32 *)
				(ring + KNOD_GDA_DB_OFF + KNOD_GDA_SQ_DB + 4))),
			   be32_to_cpu(READ_ONCE(*(const __be32 *)
				(ring + KNOD_GDA_DB_OFF + KNOD_GDA_TX_CQ_DB))));
	seq_printf(s, "q%-2d rings rq %u of %u, cq %u, sq %u, tx cq %u, doorbell %pa at 0x%llx\n",
		   q, 1U << rq_log,
		   bnxt ? 1U << KNOD_GDA_RD32(e, rq_ring_log) : 1U << rq_log,
		   1U << KNOD_GDA_RD32(e, cq_log),
		   KNOD_GDA_RD32(e, sq_mask) + 1,
		   1U << KNOD_GDA_RD32(e, tx_cq_log), &g->db_phys[q],
		   g->db_gaddr[q]);
	/* Host TX: the producer and consumer as the host keeps them in GTT
	 * and as the engine reads them in the entry, and frames waiting.
	 */
	if (g->htx[q]) {
		void *htx = g->htx[q]->kaddr + knod_gda_htx_ctl_off(g);

		seq_printf(s, "q%-2d htx gtt pc %u cc %u, entry pc %u cc %u, backlog %u\n",
			   q, READ_ONCE(*(u32 *)(htx + KNOD_PERSIST_HTX_PC)),
			   READ_ONCE(*(u32 *)(htx + KNOD_PERSIST_HTX_CC)),
			   KNOD_GDA_RD32(e, htx_pc), KNOD_GDA_RD32(e, htx_cc),
			   skb_queue_len(&g->htx_backlog[q]));
	}
	/* bnxt: the rings' firmware ids, out of their doorbell keys - what
	 * the driver logged when it built them.
	 */
	if (bnxt) {
		for (k = 0; k < KNOD_PERSIST_DB_KEYS; k++)
			key[k] = KNOD_GDA_RD64(e, db_key[k]);
		seq_printf(s, "q%-2d ids rq %llu rx cq %llu sq %llu tx cq %llu\n",
			   q, key[KNOD_PERSIST_DB_RQ] >> 32 & 0xfffff,
			   key[KNOD_PERSIST_DB_RX_CQ] >> 32 & 0xfffff,
			   key[KNOD_PERSIST_DB_SQ] >> 32 & 0xfffff,
			   key[KNOD_PERSIST_DB_TX_CQ] >> 32 & 0xfffff);
	}
	seq_printf(s, "q%-2d tx sq %llx pc %u cc %u ci %u dead %u gen %u/%u\n",
		   q, KNOD_GDA_RD64(e, sq), KNOD_GDA_RD32(e, sq_pc),
		   KNOD_GDA_RD32(e, sq_cc), KNOD_GDA_RD32(e, tx_ci),
		   KNOD_GDA_RD32(e, tx_dead), KNOD_GDA_RD32(e, tx_posted_gen),
		   KNOD_GDA_RD32(e, tx_gen));
	/* What the shader spreads packets with, not the parameter: a frame
	 * that leaves less than one stride of the page spare gets one offset,
	 * which is no spreading at all.
	 */
	bounds = g->param ? readl((void __iomem *)
				  &((struct knod_bpf_param *)g->param->kaddr)->queues[q].rx_bounds) : 0;
	seq_printf(s, "q%-2d stagger %u x %u offsets, frame %u headroom %u\n",
		   q, KNOD_GDA_RD32(e, stagger), KNOD_GDA_RD32(e, stagger_mask) + 1,
		   bounds >> 16, bounds & 0xffff);
	knod_gda_stats_next(s, g, e, q);
	if (KNOD_GDA_RD32(e, regress_dbg[0]))
		seq_printf(s, "q%-2d bound back: hits %u s2 %u by %d to %u sq %u/%u pass_cc %u cand %u\n",
			   q, KNOD_GDA_RD32(e, regress_dbg[0]),
			   KNOD_GDA_RD32(e, regress_dbg[1]),
			   (s32)KNOD_GDA_RD32(e, regress_dbg[2]),
			   KNOD_GDA_RD32(e, regress_dbg[3]),
			   KNOD_GDA_RD32(e, regress_dbg[4]),
			   KNOD_GDA_RD32(e, regress_dbg[5]),
			   KNOD_GDA_RD32(e, regress_dbg[6]),
			   KNOD_GDA_RD32(e, regress_dbg[7]));
	/* A completion for another RQ entry than its place says; on bnxt,
	 * or not a plain RX completion (type 17).  The kind is mlx5's op_own,
	 * bnxt's type.
	 */
	if (KNOD_GDA_RD32(e, sync_dbg[KNOD_PERSIST_SYNC_HITS]))
		seq_printf(s, "q%-2d cqe off entry: hits %u s2 says %u cqe says %u kind 0x%x\n",
			   q, KNOD_GDA_RD32(e, sync_dbg[KNOD_PERSIST_SYNC_HITS]),
			   KNOD_GDA_RD32(e, sync_dbg[KNOD_PERSIST_SYNC_ENTRIES]) & 0xffff,
			   KNOD_GDA_RD32(e, sync_dbg[KNOD_PERSIST_SYNC_ENTRIES]) >> 16,
			   KNOD_GDA_RD32(e, sync_dbg[KNOD_PERSIST_SYNC_KIND]));
}

static int knod_gda_stats_show(struct seq_file *s, void *unused)
{
	struct knod_gda *g = s->private;
	struct knod_persistent_mem *pm = knod_gda_mem(g);
	u64 pkts = 0, tx = 0, full = 0, rounds = 0, pass = 0, passed = 0;
	u64 pass_full = 0;
	u64 n;
	int q;

	for (q = 0; q < g->nr_queues; q++) {
		pkts += readq((void __iomem *)&pm->control.gda[q].packets);
		rounds += readq((void __iomem *)&pm->control.gda[q].rounds);
		pass += readl((void __iomem *)&pm->control.gda[q].pass_pc);
		passed += knod_gda_pass_cc(g, q);
		pass_full += readq((void __iomem *)&pm->control.gda[q].pass_full);
		tx += readq((void __iomem *)&pm->control.gda[q].tx_packets);
		full += readq((void __iomem *)&pm->control.gda[q].tx_full);
	}
	seq_printf(s, "queues:              %d\n", g->nr_queues);
	seq_printf(s, "nic format:          %s\n",
		   knod_gda_fmt_name(g->fmt));
	for (q = 0; q < g->nr_queues; q++)
		knod_gda_stats_queue(s, g, &pm->control.gda[q], q);
	seq_printf(s, "workgroup_size:      %u\n", g->wg_size);
	seq_printf(s, "waves:               %u per queue\n", g->waves);
	seq_printf(s, "stagger:             %u (parameter; per queue above)\n",
		   knod_gda_stagger);
	seq_printf(s, "engine:              %s for %s, %u bytes, lds %u\n",
		   g->engine.code == g->core_engine.code ? "core" : "ordered",
		   knod_gda_fmt_name(g->fmt),
		   g->engine.size, g->engine.lds_bytes);
	seq_printf(s, "code:                %s, %u bytes, lds %u\n",
		   g->code_is_default ? "receive kernel" : "program",
		   g->code_size, g->lds_bytes);
	seq_printf(s, "kernel_fault:        %s\n",
		   READ_ONCE(g->kernel_fault) ? "yes" : "no");
	seq_printf(s, "shader_launches:     %llu\n", g->launches);
	seq_printf(s, "shader_stops:        %llu\n", g->stops);
	seq_printf(s, "stop_shutdown:       %llu\n",
		   g->stop_reasons[KNOD_GDA_STOP_SHUTDOWN]);
	seq_printf(s, "stop_program:        %llu\n",
		   g->stop_reasons[KNOD_GDA_STOP_PROGRAM]);
	seq_printf(s, "rx_packets:          %llu\n", pkts);
	seq_printf(s, "tx_packets:          %llu\n", tx);
	seq_printf(s, "tx_full:             %llu\n", full);
	seq_printf(s, "rounds:              %llu\n", rounds);
	seq_printf(s, "pass_packets:        %llu\n", pass);
	seq_printf(s, "pass_done:           %llu\n", passed);
	seq_printf(s, "pass_full:           %llu\n", pass_full);
	seq_printf(s, "pause_requests:      %llu\n", g->pause_requests);
	seq_printf(s, "pause_acks:          %llu\n", g->pause_acks);
	seq_printf(s, "pause_program:       %llu\n",
		   g->pause_reasons[KNOD_GDA_PAUSE_PROGRAM]);
	seq_printf(s, "pause_host_map:      %llu\n",
		   g->pause_reasons[KNOD_GDA_PAUSE_HOST_MAP]);
	seq_printf(s, "pause_map_gc:        %llu\n",
		   g->pause_reasons[KNOD_GDA_PAUSE_MAP_GC]);
	seq_printf(s, "pause_ipsec_sa:      %llu\n",
		   g->pause_reasons[KNOD_GDA_PAUSE_IPSEC_SA]);
	n = atomic64_read(&g->htx_wait_n);
	seq_printf(s, "htx_wait_avg_ns:     %llu (%llu frames)\n",
		   n ? atomic64_read(&g->htx_wait_ns) / n : 0, n);
	n = atomic64_read(&g->htx_sdma_n);
	seq_printf(s, "htx_sdma_avg_ns:     %llu (%llu jobs)\n",
		   n ? atomic64_read(&g->htx_sdma_ns) / n : 0, n);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(knod_gda_stats);

/* Debug: a frame written here, whole, goes out on queue 0, as an skb would. */
static ssize_t knod_gda_tx_write(struct file *file, const char __user *buf,
				 size_t len, loff_t *ppos)
{
	struct knod_gda *g = file->private_data;
	struct sk_buff *skb;

	if (!len || len > PAGE_SIZE)
		return -EINVAL;
	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	if (copy_from_user(skb_put(skb, len), buf, len)) {
		kfree_skb(skb);
		return -EFAULT;
	}
	knod_gda_xmit_skb(g, 0, skb, 0);
	return len;
}

/*
 * Debug: memcpy into queue 0's host TX slots against into plain kernel
 * memory, from a source warm in the cache and from one that is not.
 */
static u64 knod_gda_copy_ns(void *dst, size_t stride, const void *src,
			    size_t src_bytes, u32 n)
{
	u64 t = ktime_get_ns();
	u32 i;

	for (i = 0; i < n; i++)
		memcpy(dst + (size_t)(i % KNOD_GDA_HTX_SLOTS) * stride +
		       KNOD_PERSIST_HTX_HEAD,
		       src + ((size_t)i * PAGE_SIZE) % src_bytes, 3712);
	return ktime_get_ns() - t;
}

static int knod_gda_tx_bench_show(struct seq_file *s, void *unused)
{
	struct knod_gda *g = s->private;
	size_t cold = SZ_64M, warm = SZ_64K, bytes;
	void *src, *plain;
	u32 n = 16384, r;

	if (!g->htx[0])
		return -ENODEV;
	src = vmalloc(cold);
	plain = vmalloc(KNOD_GDA_HTX_RING_OFF);
	if (!src || !plain) {
		vfree(src);
		vfree(plain);
		return -ENOMEM;
	}
	memset(src, 0x5a, cold);
	memset(plain, 0, KNOD_GDA_HTX_RING_OFF);
	bytes = (size_t)n * 3712;
	for (r = 0; r < 2; r++) {
		size_t sb = r ? cold : warm;
		u64 a, b;

		a = knod_gda_copy_ns(g->htx[0]->kaddr, PAGE_SIZE, src, sb, n);
		b = knod_gda_copy_ns(plain, PAGE_SIZE, src, sb, n);
		seq_printf(s, "%s source: htx slots %llu MB/s, plain %llu MB/s\n",
			   r ? "cold" : "warm", bytes * 1000 / max(a, 1ULL),
			   bytes * 1000 / max(b, 1ULL));
	}
	vfree(plain);
	vfree(src);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(knod_gda_tx_bench);

/* Debug: the AGP aperture, and the kernel's SDMA through it. */
static int knod_gda_aperture_show(struct seq_file *s, void *unused)
{
	return knod_agp_show(s, knod_gda_adev(s->private));
}
DEFINE_SHOW_ATTRIBUTE(knod_gda_aperture);

static int knod_gda_sdma_bench_show(struct seq_file *s, void *unused)
{
	return knod_agp_sdma_bench(s, knod_gda_adev(s->private));
}
DEFINE_SHOW_ATTRIBUTE(knod_gda_sdma_bench);

/*
 * Debug: one frame through host TX on queue 0, best on an idle queue, and
 * when the host sees each step after queueing it: the SDMA job's fence, the
 * engine taking it (its consumer passes it), and a NIC completion after it.
 * It goes to our own MAC with the local experimental EtherType.
 */
static int knod_gda_tx_probe_show(struct seq_file *s, void *unused)
{
	struct knod_gda *g = s->private;
	struct net_device *dev = g->knodev->netdev;
	struct knod_persistent_gda __iomem *e;
	u64 t0, now, end, submit, fence, took = 0, done = 0;
	u32 k, sq0, *cc;
	struct sk_buff *skb;
	struct ethhdr *eh;

	if (!g->htx[0] || !READ_ONCE(g->htx_on[0]))
		return -ENETDOWN;
	skb = alloc_skb(64, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	eh = skb_put_zero(skb, 64);
	ether_addr_copy(eh->h_dest, dev->dev_addr);
	ether_addr_copy(eh->h_source, dev->dev_addr);
	eh->h_proto = htons(ETH_P_802_EX1);
	skb->dev = dev;

	e = &((struct knod_persistent_mem __iomem *)knod_gda_mem(g))->control.gda[0];
	cc = g->htx[0]->kaddr + knod_gda_htx_ctl_off(g) + KNOD_PERSIST_HTX_CC;
	k = READ_ONCE(*(u32 *)(g->htx[0]->kaddr + knod_gda_htx_ctl_off(g) +
			       KNOD_PERSIST_HTX_PC));
	sq0 = KNOD_GDA_RD32(e, sq_cc);
	WRITE_ONCE(g->htx_probe_submit, 0);
	WRITE_ONCE(g->htx_probe_fence, 0);
	WRITE_ONCE(g->htx_probe, skb);
	t0 = ktime_get_ns();
	knod_gda_xmit_skb(g, 0, skb, 0);
	end = t0 + 100 * NSEC_PER_MSEC;
	while ((now = ktime_get_ns()) < end) {
		if (!took && (s32)(READ_ONCE(*cc) - k) > 0)
			took = now;
		if (took && (s32)(KNOD_GDA_RD32(e, sq_cc) - sq0) > 0) {
			done = now;
			break;
		}
		udelay(1);
	}
	submit = READ_ONCE(g->htx_probe_submit);
	fence = READ_ONCE(g->htx_probe_fence);
	WRITE_ONCE(g->htx_probe, NULL);
	seq_printf(s, "probe q0: submit +%llu us, fence +%llu us, engine took +%llu us, NIC done +%llu us\n",
		   submit ? (submit - t0) / 1000 : 0,
		   fence ? (fence - t0) / 1000 : 0,
		   took ? (took - t0) / 1000 : 0,
		   done ? (done - t0) / 1000 : 0);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(knod_gda_tx_probe);

static const struct file_operations knod_gda_tx_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = knod_gda_tx_write,
};

/*
 * Feature select: the engine's accel memory, and the rings offered to the NIC.
 * The receive kernel is what runs until something installs other code.
 */
int knod_gda_activate(struct knod *knod)
{
	struct knod_dev *knodev = knod->accel->knodev;
	struct knod_blob_callee engine;
	struct netlink_ext_ack extack = {};
	struct net_dmq_layout layout;
	struct knod_gda *g;
	u32 wg_size = knod_gda_workgroups, nr_regions;
	int err, i;

	if (knod->isa_version != 10 && knod->isa_version != 11) {
		pr_warn("knod: gfx%d has no persistent shader\n",
			knod->isa_version);
		return -EOPNOTSUPP;
	}
	if (wg_size < 64 || wg_size > 64 * KNOD_PERSIST_GDA_WAVES_MAX ||
	    wg_size % 64) {
		pr_warn("knod: knod_workgroups=%u is not 64 to %u in 64s, using 256\n",
			wg_size, 64 * KNOD_PERSIST_GDA_WAVES_MAX);
		wg_size = 256;
	}
	err = knod_gda_geometry_check(knod, wg_size);
	if (err)
		return err;

	g = kzalloc_obj(*g, GFP_KERNEL);
	if (!g)
		return -ENOMEM;
	g->knod = knod;
	g->knodev = knodev;
	INIT_LIST_HEAD(&g->hdp_link);
	INIT_WORK(&g->restart, knod_gda_restart);
	g->wg_size = wg_size;
	g->waves = wg_size / 64;
	g->nr_queues = knod_gda_active_rxq_count(knodev->netdev);
	mutex_init(&g->op_lock);
	mutex_init(&g->client_lock);
	init_waitqueue_head(&g->op_wq);
	init_waitqueue_head(&g->pass_wq);
	for (i = 0; i < KNOD_SPSC_MAX; i++)
		skb_queue_head_init(&g->htx_backlog[i]);
	err = -EOPNOTSUPP;
	/* A channel is a CU and a CPU: a percpu map's instance i is queue i,
	 * and there are as many as CPUs.  A channel left out would run on the
	 * host, unseen.
	 */
	if (g->nr_queues > KNOD_SPSC_MAX ||
	    g->nr_queues > num_possible_cpus()) {
		pr_warn("knod: %s has %u channels, more than %u: set fewer with ethtool -L\n",
			netdev_name(knodev->netdev), g->nr_queues,
			min_t(u32, KNOD_SPSC_MAX, num_possible_cpus()));
		goto err_free;
	}
	if (!g->nr_queues || g->nr_queues > knod->cu_count) {
		pr_warn("knod: %d RX queues for %d CUs, one persistent workgroup each\n",
			g->nr_queues, knod->cu_count);
		goto err_free;
	}
	/* The NIC's format, which the kernel must know before it looks for
	 * an engine for it in the blob.
	 */
	err = net_devmem_queue_query(knodev->netdev, 0, &layout, &extack);
	if (err || !knod_gda_regions(layout.fmt, &nr_regions)) {
		pr_warn("knod: %s has no rings the engine runs: %d (%s)\n",
			netdev_name(knodev->netdev), err,
			extack._msg ?: "format unknown");
		err = -EOPNOTSUPP;
		goto err_free;
	}
	g->fmt = layout.fmt;
	g->core_engine.code = knod_blob_find_call(&knod->core_blob,
						  KNOD_BLOB_GDA_ENGINE,
						  g->fmt,
						  &g->core_engine.size,
						  &engine);
	g->core_engine.call = engine.patch;
	g->core_engine.lds_bytes = KNOD_PERSIST_GDA_LDS_BYTES;
	g->engine = g->core_engine;
	g->code = knod_gda_default_code(knod, &g->code_size);
	if (!g->engine.code || !g->engine.call || !g->code ||
	    g->engine.size + g->code_size >
	    knod->kernel->size - KNOD_GDA_ENTRY_OFFSET) {
		pr_warn("knod: core blob has no engine for NIC format %u, or no receive program\n",
			g->fmt);
		goto err_free;
	}
	g->code_is_default = true;

	err = -ENOMEM;
	g->control = knod_alloc_mem(knod, KNOD_PERSIST_BYTES,
				    KFD_IOC_ALLOC_MEM_FLAGS_VRAM |
				    KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
				    KFD_IOC_ALLOC_MEM_FLAGS_COHERENT);
	if (IS_ERR_OR_NULL(g->control)) {
		g->control = NULL;
		goto err_free;
	}
	/* Shader starts keep the rings' state; this is where it begins clean. */
	memset_io((void __iomem *)g->control->kaddr, 0,
		  sizeof(struct knod_persistent_mem));

	knod->gda = g;
	err = knod_gda_rings_init(g);
	if (err) {
		pr_warn("knod: no accel memory for the NIC's rings: %d\n", err);
		knod_gda_deactivate(knod);
		return err;
	}
	err = knod_gda_htx_entities(g);
	if (err) {
		knod_gda_deactivate(knod);
		return err;
	}
	g->htx_task = kthread_run(knod_gda_htx_thread, g, "knod_htx/%d",
				  g->knodev->netdev->ifindex);
	if (IS_ERR(g->htx_task)) {
		err = PTR_ERR(g->htx_task);
		g->htx_task = NULL;
		knod_gda_deactivate(knod);
		return err;
	}
	sched_set_fifo_low(g->htx_task);
	knod_gda_write_descriptor(knod);
	if (knod->debug_dir) {
		debugfs_create_file("gda", 0444, knod->debug_dir, g,
				    &knod_gda_stats_fops);
		debugfs_create_file("gda_tx", 0200, knod->debug_dir, g,
				    &knod_gda_tx_fops);
		debugfs_create_file("gda_tx_bench", 0400, knod->debug_dir, g,
				    &knod_gda_tx_bench_fops);
		debugfs_create_file("gda_aperture", 0400, knod->debug_dir, g,
				    &knod_gda_aperture_fops);
		debugfs_create_file("gda_sdma_bench", 0400, knod->debug_dir, g,
				    &knod_gda_sdma_bench_fops);
		debugfs_create_file("gda_tx_probe", 0400, knod->debug_dir, g,
				    &knod_gda_tx_probe_fops);
	}
	rcu_assign_pointer(knod->process->knod_gda, g);
	WRITE_ONCE(g->ready, true);
	/* Up already: the queues were rebuilt as they were bound, with no
	 * engine to start on them then.
	 */
	if (netif_running(knodev->netdev))
		knod_gda_start(knod);
	return 0;

err_free:
	kfree(g);
	return err;
}

void knod_gda_deactivate(struct knod *knod)
{
	struct knod_gda *g = knod->gda;

	if (!g)
		return;
	RCU_INIT_POINTER(knod->process->knod_gda, NULL);
	synchronize_rcu();
	if (knod->debug_dir) {
		debugfs_lookup_and_remove("gda", knod->debug_dir);
		debugfs_lookup_and_remove("gda_tx", knod->debug_dir);
		debugfs_lookup_and_remove("gda_tx_bench", knod->debug_dir);
		debugfs_lookup_and_remove("gda_aperture", knod->debug_dir);
		debugfs_lookup_and_remove("gda_sdma_bench", knod->debug_dir);
		debugfs_lookup_and_remove("gda_tx_probe", knod->debug_dir);
	}
	WRITE_ONCE(g->want, false);
	cancel_work_sync(&g->restart);
	knod_gda_stop(knod);
	knod_gda_unmap_doorbells(g);
	knod_gda_rings_exit(g);
	if (g->control)
		knod_free_mem(knod, g->control);
	knod->gda = NULL;
	kfree(g);
}
