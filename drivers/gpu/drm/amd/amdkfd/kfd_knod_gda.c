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
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/netdevice.h>
#include "kfd_priv.h"
#include "kfd_knod.h"
#include "knod_param.h"
#include "knod_persistent.h"

/* Lanes in a queue's workgroup; a wave of them per 64, up to
 * KNOD_PERSIST_GDA_WAVES_MAX taking packets.
 */
static unsigned int knod_gda_workgroups = 256;
MODULE_PARM_DESC(knod_workgroups, "KNOD: lanes in each queue's persistent workgroup: 64, 128, 192 or 256");
module_param_named(knod_workgroups, knod_gda_workgroups, uint, 0444);

/* One packet a page, so there is always room to move a packet's start off the
 * offset every other one has; all at one offset put every packet on one
 * memory channel.  Which step spreads them best depends on the GPU's address
 * hash: 128 on Navi 21, where 64 and 256 both did worse.  Zero leaves them
 * where they were.  Fixed at load: the RQ is posted once per build of the
 * rings.
 */
static unsigned int knod_gda_stagger = 128;
MODULE_PARM_DESC(knod_gda_stagger, "KNOD: bytes between the offsets packets start at, a power of two (0 = one offset)");
module_param_named(knod_gda_stagger, knod_gda_stagger, uint, 0444);

struct knod_persistent_mem {
	struct knod_persistent_control control;
	struct amd_signal terminal;
};

static_assert(offsetof(struct knod_persistent_control, stop) == KNOD_PERSIST_STOP);
static_assert(offsetof(struct knod_persistent_control, pause) == KNOD_PERSIST_PAUSE);
static_assert(offsetof(struct knod_persistent_control, gda_param) ==
	      KNOD_PERSIST_GDA_PARAM);
static_assert(offsetof(struct knod_persistent_control, gda_lds) ==
	      KNOD_PERSIST_GDA_LDS);
static_assert(offsetof(struct knod_persistent_control, gda_waves) ==
	      KNOD_PERSIST_GDA_WAVES);
static_assert(offsetof(struct knod_persistent_control, tx_db) == KNOD_PERSIST_TX_DB);
static_assert(offsetof(struct knod_persistent_control, gda) == KNOD_PERSIST_GDA);
static_assert(KNOD_SPSC_MAX <= KNOD_PERSIST_MAX_QUEUES);
static_assert(sizeof(struct knod_persistent_mem) <= KNOD_PERSIST_BYTES);
static_assert(sizeof(struct knod_persistent_gda) == KNOD_PERSIST_GDA_BYTES);
static_assert(offsetof(struct knod_persistent_gda, rx_dma) == KNOD_PERSIST_GDA_RX_DMA);
static_assert(offsetof(struct knod_persistent_gda, packets) == KNOD_PERSIST_GDA_PACKETS);
static_assert(offsetof(struct knod_persistent_gda, rounds) == KNOD_PERSIST_GDA_ROUNDS);
static_assert(offsetof(struct knod_persistent_gda, rq_log) == KNOD_PERSIST_GDA_RQ_LOG);
static_assert(offsetof(struct knod_persistent_gda, rq_log_stride) ==
	      KNOD_PERSIST_GDA_RQ_LOG_STRIDE);
static_assert(offsetof(struct knod_persistent_gda, cq_log) == KNOD_PERSIST_GDA_CQ_LOG);
static_assert(offsetof(struct knod_persistent_gda, frag) == KNOD_PERSIST_GDA_FRAG);
static_assert(offsetof(struct knod_persistent_gda, headroom) == KNOD_PERSIST_GDA_HEADROOM);
static_assert(offsetof(struct knod_persistent_gda, mkey_be) == KNOD_PERSIST_GDA_MKEY);
static_assert(offsetof(struct knod_persistent_gda, live) == KNOD_PERSIST_GDA_LIVE);
static_assert(offsetof(struct knod_persistent_gda, gen) == KNOD_PERSIST_GDA_GEN);
static_assert(offsetof(struct knod_persistent_gda, rx_base) == KNOD_PERSIST_GDA_RX_BASE);
static_assert(offsetof(struct knod_persistent_gda, ci) == KNOD_PERSIST_GDA_CI);
static_assert(offsetof(struct knod_persistent_gda, posted_gen) ==
	      KNOD_PERSIST_GDA_POSTED_GEN);
static_assert(offsetof(struct knod_persistent_gda, pause_ack) ==
	      KNOD_PERSIST_GDA_PAUSE_ACK);
static_assert(offsetof(struct knod_persistent_gda, sq) == KNOD_PERSIST_GDA_SQ);
static_assert(offsetof(struct knod_persistent_gda, sqn) == KNOD_PERSIST_GDA_SQN);
static_assert(offsetof(struct knod_persistent_gda, sq_mask) == KNOD_PERSIST_GDA_SQ_MASK);
static_assert(offsetof(struct knod_persistent_gda, tx_mkey_be) ==
	      KNOD_PERSIST_GDA_TX_MKEY);
static_assert(offsetof(struct knod_persistent_gda, tx_cq_log) ==
	      KNOD_PERSIST_GDA_TX_CQ_LOG);
static_assert(offsetof(struct knod_persistent_gda, tx_gen) == KNOD_PERSIST_GDA_TX_GEN);
static_assert(offsetof(struct knod_persistent_gda, tx_packets) ==
	      KNOD_PERSIST_GDA_TX_PACKETS);
static_assert(offsetof(struct knod_persistent_gda, tx_full) == KNOD_PERSIST_GDA_TX_FULL);
static_assert(offsetof(struct knod_persistent_gda, sq_pc) == KNOD_PERSIST_GDA_SQ_PC);
static_assert(offsetof(struct knod_persistent_gda, sq_cc) == KNOD_PERSIST_GDA_SQ_CC);
static_assert(offsetof(struct knod_persistent_gda, tx_ci) == KNOD_PERSIST_GDA_TX_CI);
static_assert(offsetof(struct knod_persistent_gda, tx_posted_gen) ==
	      KNOD_PERSIST_GDA_TX_POSTED_GEN);
static_assert(offsetof(struct knod_persistent_gda, stagger) == KNOD_PERSIST_GDA_STAGGER);
static_assert(offsetof(struct knod_persistent_gda, stagger_mask) ==
	      KNOD_PERSIST_GDA_STAGGER_MASK);
static_assert(offsetof(struct knod_persistent_gda, pass_ring) ==
	      KNOD_PERSIST_GDA_PASS_RING);
static_assert(offsetof(struct knod_persistent_gda, pass_mask) ==
	      KNOD_PERSIST_GDA_PASS_MASK);
static_assert(offsetof(struct knod_persistent_gda, pass_pc) == KNOD_PERSIST_GDA_PASS_PC);
static_assert(offsetof(struct knod_persistent_gda, pass_cc) == KNOD_PERSIST_GDA_PASS_CC);
static_assert(offsetof(struct knod_persistent_gda, pass_floor) ==
	      KNOD_PERSIST_GDA_PASS_FLOOR);
static_assert(KNOD_GDA_DB_OFF + KNOD_GDA_RQ_DB == KNOD_PERSIST_RING_RQ_DB);
static_assert(KNOD_GDA_DB_OFF + KNOD_GDA_CQ_DB == KNOD_PERSIST_RING_CQ_DB);
/* The send counter is the record's second; see MLX5_SND_DBR. */
static_assert(KNOD_GDA_DB_OFF + KNOD_GDA_SQ_DB + 4 == KNOD_PERSIST_RING_SQ_DB);
static_assert(KNOD_GDA_DB_OFF + KNOD_GDA_TX_CQ_DB == KNOD_PERSIST_RING_TX_CQ_DB);
static_assert(KNOD_PERSIST_RING_RQ_OFF == KNOD_GDA_RQ_OFF);
static_assert(KNOD_PERSIST_RING_CQ_OFF == KNOD_GDA_CQ_OFF);
static_assert(KNOD_PERSIST_RING_TX_CQ_OFF == KNOD_GDA_TX_CQ_OFF);
static_assert(KNOD_PERSIST_RING_RQPOS_OFF == KNOD_GDA_RQPOS_OFF);
static_assert(KNOD_PERSIST_RING_PASS_RQPOS_OFF == KNOD_GDA_PASS_RQPOS_OFF);
static_assert(KNOD_GDA_RQPOS_BYTES / 4 == KNOD_TXSQ_BYTES / 64);
/* A held RQ entry per unfinished PASS: never more of them than the RQ has. */
static_assert(KNOD_GDA_PASS_RQPOS_BYTES / 4 == KNOD_PERSIST_GDA_PASS_ENTRIES);
static_assert(KNOD_GDA_RQ_BYTES / 64 <= KNOD_PERSIST_GDA_PASS_ENTRIES);

#define KNOD_GDA_ENTRY_OFFSET		1024
#define KNOD_GDA_PASS_RING_BYTES	(KNOD_PERSIST_GDA_PASS_ENTRIES * 8)

static struct knod_persistent_mem *knod_gda_mem(struct knod_gda *g)
{
	return g->control->kaddr;
}

/* Queue @q's PASS ring, in the parameter block past the parameters. */
static size_t knod_gda_pass_ring_off(u32 q)
{
	return ALIGN(sizeof(struct knod_bpf_param), PAGE_SIZE) +
	       (size_t)q * KNOD_GDA_PASS_RING_BYTES;
}

static unsigned int knod_gda_active_rxq_count(struct net_device *netdev)
{
	unsigned int nr_rxq;

	nr_rxq = READ_ONCE(netdev->real_num_rx_queues);
	if (!nr_rxq)
		nr_rxq = netdev->num_rx_queues;

	/* Also cap by CPU count: a percpu map keeps one instance per queue and
	 * aggregates per CPU, so more queues than CPUs has nowhere to report
	 * the excess.
	 */
	nr_rxq = min_t(unsigned int, nr_rxq, KNOD_SPSC_MAX);
	return min_t(unsigned int, nr_rxq, num_possible_cpus());
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
static void knod_gda_write_descriptor(struct knod *knod)
{
	struct kernel_descriptor *kd = knod->kernels[0]->kaddr;

	memset(kd, 0, sizeof(*kd));
	kd->kernarg_size = 64;
	kd->kernel_code_entry_byte_offset = KNOD_GDA_ENTRY_OFFSET;

	/*
	 * User SGPRs load in this order, disabled ones skipped: private
	 * segment buffer s[0:3], dispatch s[4:5], queue s[6:7], kernarg
	 * s[8:9], dispatch id s[10:11].  No flat scratch - the stack is in
	 * LDS.  The workgroup ids follow at s12 and s13.
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
	kd->compute_pgm_rsrc2.enable_sgpr_workgroup_id_x = 1;
	kd->compute_pgm_rsrc2.enable_sgpr_workgroup_id_y = 1;
	kd->compute_pgm_rsrc2.enable_vgpr_workitem_id = 1;
}

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
	WRITE_ONCE(mem->control.stop, 1);
	deadline = jiffies + msecs_to_jiffies(1000);
	while (READ_ONCE(mem->terminal.value)) {
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
	p.group_segment_size = g->lds_bytes + KNOD_PERSIST_GDA_LDS_BYTES;
	p.kernel_object = g->knod->kernels[0]->gaddr;
	p.kernarg_address = g->control->gaddr;
	completion_signal = g->control->gaddr +
		offsetof(struct knod_persistent_mem, terminal);
	/* All control initialization precedes launch. */
	wmb();
	knod_setup_header_signal(g->knod, &p, 0, completion_signal);
	g->running = true;
	g->launches++;
}

/*
 * XDP_PASS: offer the host copy whatever the shader has appended to each
 * queue's PASS ring since the last look.  Whatever the copy has no room for
 * now stays for the next look; the shader holds those packets' RQ entries
 * meanwhile.
 */
static void knod_gda_pass_poll(struct knod_gda *g)
{
	struct knod_persistent_mem *mem = knod_gda_mem(g);
	struct spsc_pass_bd bds[KNOD_DEFAULT_PASS_SLOTS];
	u32 pc, seen, n, k, e;
	const u64 *ring;
	int i, taken;
	u64 v;

	rcu_read_lock_bh();
	for (i = 0; i < g->nr_queues; i++) {
		pc = READ_ONCE(mem->control.gda[i].pass_pc);
		seen = g->pass_seen[i];
		if (pc == seen)
			continue;
		/* The entries before the count that says they are there. */
		dma_rmb();
		ring = g->param->kaddr + knod_gda_pass_ring_off(i);
		while (seen != pc) {
			n = min_t(u32, pc - seen, KNOD_DEFAULT_PASS_SLOTS);
			for (k = 0; k < n; k++) {
				e = (seen + k) &
				    (KNOD_PERSIST_GDA_PASS_ENTRIES - 1);
				v = READ_ONCE(ring[e]);
				bds[k].page_idx = lower_32_bits(v);
				bds[k].off = upper_32_bits(v) & 0xffff;
				bds[k].len = upper_32_bits(v) >> 16;
			}
			taken = knod_d2h_copy(g->knodev, i, bds, n);
			seen += taken;
			if (taken < n)
				break;
		}
		g->pass_seen[i] = seen;
	}
	rcu_read_unlock_bh();
}

/*
 * Offer the NIC each queue's ring buffer and XDP SQ buffer in accel memory,
 * and give the shader the NIC's address for every RX page it may send from,
 * and the block a program's context lives in, with the PASS rings past it.
 * The NIC builds its queues on them when it next brings the interface up.
 */
static int knod_gda_rings_init(struct knod_gda *g)
{
	struct knod_dev *knodev = g->knodev;
	struct knod *knod = g->knod;
	struct knod_bpf_param *param;
	struct knod_mem *mem;
	unsigned int n, pages;
	int i;

	mem = knod_alloc_mem(knod, knod_gda_pass_ring_off(g->nr_queues),
			     KFD_IOC_ALLOC_MEM_FLAGS_GTT |
			     KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
			     KFD_IOC_ALLOC_MEM_FLAGS_COHERENT);
	if (IS_ERR_OR_NULL(mem))
		return -ENOMEM;
	param = mem->kaddr;
	memset(param, 0, sizeof(*param));
	param->page_shift = PAGE_SHIFT;
	param->ktime_ns = ktime_get_ns();
	g->param = mem;

	for (i = 0; i < g->nr_queues; i++) {
		pages = knod->buf[i]->size >> PAGE_SHIFT;
		mem = knod_alloc_mem(knod, pages * sizeof(u64),
				     KFD_IOC_ALLOC_MEM_FLAGS_VRAM |
				     KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE);
		if (IS_ERR_OR_NULL(mem))
			return -ENOMEM;
		n = knod_dev_rx_dma_addrs(knodev, i, mem->kaddr, pages);
		if (n != pages) {
			pr_warn("knod: queue %d: %u of %u RX pages bound\n",
				i, n, pages);
			knod_free_mem(knod, mem);
			return -EINVAL;
		}
		g->rx_dma[i] = mem;
		WRITE_ONCE(knodev->wpriv[i].tx_sq_dmabuf,
			   knod->txsq[i]->mem->dmabuf);
		WRITE_ONCE(knodev->wpriv[i].gda_rx_kaddr, knod->gda_rx[i]->kaddr);
		WRITE_ONCE(knodev->wpriv[i].gda_rx_dmabuf,
			   knod->gda_rx[i]->mem->dmabuf);
	}
	return 0;
}

static void knod_gda_rings_exit(struct knod_gda *g)
{
	int i;

	/* An SQ or RQ the NIC already built keeps its own mapping of its
	 * buffer until the channel closes; this only stops new ones.
	 */
	for (i = 0; i < KNOD_SPSC_MAX; i++) {
		WRITE_ONCE(g->knodev->wpriv[i].tx_sq_dmabuf, NULL);
		WRITE_ONCE(g->knodev->wpriv[i].gda_rx_dmabuf, NULL);
		WRITE_ONCE(g->knodev->wpriv[i].gda_rx_kaddr, NULL);
		if (g->rx_dma[i])
			knod_free_mem(g->knod, g->rx_dma[i]);
		g->rx_dma[i] = NULL;
	}
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
}

/*
 * Put each queue's NIC TX doorbell in the GPU's address space, so the shader
 * can ring it without the CPU.
 *
 * Done at every shader start rather than once at activate: the NIC publishes
 * the doorbell when it builds its RQs, which is after the feature activated.
 * Only a doorbell that moved is remapped.  A queue whose NIC publishes none
 * keeps a zero entry, and its XDP_TX drops.
 */
static void knod_gda_map_doorbells(struct knod_gda *g)
{
	struct knod_mem *mem;
	phys_addr_t phys;
	int i;

	for (i = 0; i < g->nr_queues; i++) {
		phys = READ_ONCE(g->knodev->wpriv[i].tx_db_phys);
		if (phys == g->db_phys[i])
			continue;

		knod_gda_unmap_doorbell(g, i);
		g->db_phys[i] = phys;
		if (!phys) {
			pr_info("knod: queue %d: NIC publishes no TX doorbell\n",
				i);
			continue;
		}

		mem = knod_map_mmio(g->knod, phys & PAGE_MASK, PAGE_SIZE);
		if (IS_ERR(mem)) {
			pr_warn("knod: queue %d doorbell %pa not mappable: %ld\n",
				i, &phys, PTR_ERR(mem));
			continue;
		}
		g->db_mem[i] = mem;
		g->db_gaddr[i] = mem->gaddr + offset_in_page((unsigned long)phys);
	}
}

static void knod_gda_unmap_doorbells(struct knod_gda *g)
{
	int i;

	for (i = 0; i < KNOD_SPSC_MAX; i++) {
		knod_gda_unmap_doorbell(g, i);
		g->db_phys[i] = 0;
	}
}

/* As many offsets, up to eight, as leave the furthest frame in its page;
 * a power of two of them, so the shader masks.
 */
static void knod_gda_stagger_init(struct knod_persistent_gda *e, u32 bounds)
{
	u32 stride = READ_ONCE(knod_gda_stagger);
	u32 frame = bounds >> 16, n;

	e->stagger = 0;
	e->stagger_mask = 0;
	if (!stride || !is_power_of_2(stride) || !frame || frame >= PAGE_SIZE)
		return;
	n = clamp_t(u32, (PAGE_SIZE - frame) / stride, 1, 8);
	e->stagger = stride;
	e->stagger_mask = rounddown_pow_of_two(n) - 1;
}

/* What the shader reads for each queue whose rings the NIC gave us. */
static void knod_gda_rings_control(struct knod_gda *g,
				   struct knod_persistent_mem *mem)
{
	struct knod_bpf_param *param = g->param->kaddr;
	struct knod *knod = g->knod;
	struct knod_work_priv *wpriv;
	struct knod_persistent_gda *e;
	int i;

	for (i = 0; i < g->nr_queues; i++) {
		wpriv = &g->knodev->wpriv[i];
		e = &mem->control.gda[i];
		e->live = 0;
		if (!READ_ONCE(wpriv->gda_rx_live)) {
			pr_info("knod: queue %d receive rings not ours\n", i);
			continue;
		}
		smp_rmb();	/* pairs with the NIC's publish: live last */
		e->ring = knod->gda_rx[i]->gaddr;
		e->rx_dma = g->rx_dma[i]->gaddr;
		e->rq_log = READ_ONCE(wpriv->gda_rq_log_sz);
		e->rq_log_stride = READ_ONCE(wpriv->gda_rq_log_stride);
		e->cq_log = READ_ONCE(wpriv->gda_cq_log_sz);
		e->frag = READ_ONCE(wpriv->gda_frag_size);
		e->headroom = READ_ONCE(wpriv->gda_headroom);
		e->mkey_be = (__force u32)READ_ONCE(wpriv->gda_mkey_be);
		e->gen = READ_ONCE(wpriv->gda_rx_gen);
		knod_gda_stagger_init(e, READ_ONCE(wpriv->rx_bounds));
		/* pass_pc, pass_cc and pass_floor carry over, as ci does. */
		e->pass_ring = g->param->gaddr + knod_gda_pass_ring_off(i);
		e->pass_mask = KNOD_PERSIST_GDA_PASS_ENTRIES - 1;
		WRITE_ONCE(wpriv->gda_pass_cc, &e->pass_cc);
		e->rx_base = knod->buf[i]->gaddr;
		e->sq = 0;
		if (READ_ONCE(wpriv->gda_tx_live) && READ_ONCE(wpriv->tx_sqn) &&
		    g->db_gaddr[i]) {
			smp_rmb();	/* pairs with the NIC's publish */
			e->sqn = READ_ONCE(wpriv->tx_sqn);
			e->sq_mask = READ_ONCE(wpriv->tx_sq_mask);
			e->tx_mkey_be = (__force u32)READ_ONCE(wpriv->tx_mkey_be);
			e->tx_cq_log = READ_ONCE(wpriv->gda_tx_cq_log_sz);
			e->tx_gen = READ_ONCE(wpriv->gda_tx_gen);
			e->sq = knod->txsq[i]->gaddr;
		} else {
			pr_info("knod: queue %d XDP SQ not ours (live %u sqn %u db %llx), XDP_TX drops\n",
				i, READ_ONCE(wpriv->gda_tx_live),
				READ_ONCE(wpriv->tx_sqn), g->db_gaddr[i]);
		}
		/* ci, posted_gen and pause_ack are the shader's; a ring of a
		 * new generation is how it knows to drop them.
		 */
		e->live = 1;
		param->queues[i].rx_bounds = READ_ONCE(wpriv->rx_bounds);
	}
	mem->control.gda_param = g->param->gaddr;
	mem->control.gda_lds = g->lds_bytes;
	mem->control.gda_waves = g->waves;
}

static void knod_gda_control_init(struct knod_gda *g)
{
	struct knod_persistent_mem *mem = knod_gda_mem(g);
	int i;

	WARN_ON_ONCE(g->running);
	/* Everything but the rings' state: the rings carried on while no
	 * shader ran, and the next one picks up where the last left them.
	 */
	memset(mem, 0, offsetof(struct knod_persistent_mem, control.gda));
	memset((u8 *)mem + offsetofend(struct knod_persistent_mem, control.gda),
	       0, sizeof(*mem) -
	       offsetofend(struct knod_persistent_mem, control.gda));
	for (i = 0; i < g->nr_queues; i++)
		mem->control.tx_db[i] = g->db_gaddr[i];
	knod_gda_rings_control(g, mem);
	mem->control.version = KNOD_PERSIST_VERSION;
	mem->terminal = *(struct amd_signal *)
		g->knod->kaql[0].queue_signal->kaddr;
	mem->terminal.value = 1;
	dma_wmb();
}

/* Code into the slot, where the stopped shader's next launch finds it. */
static void knod_gda_copy_code(struct knod_gda *g)
{
	struct knod_mem *slot = g->knod->kernels[0];

	memcpy(slot->kaddr + KNOD_GDA_ENTRY_OFFSET, g->code, g->code_size);
	memset(slot->kaddr + KNOD_GDA_ENTRY_OFFSET + g->code_size, 0,
	       slot->size - KNOD_GDA_ENTRY_OFFSET - g->code_size);
	/*
	 * kernels[] is write-combining VRAM: drain the WC buffers before the
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
	WRITE_ONCE(mem->control.pause, value);
	deadline = jiffies + msecs_to_jiffies(1000);
	do {
		parked = true;
		for (i = 0; i < g->nr_queues; i++)
			if (READ_ONCE(mem->control.gda[i].live) &&
			    READ_ONCE(mem->control.gda[i].pause_ack) != value)
				parked = false;
		if (parked) {
			/* What the parked waves wrote, before the host reads. */
			dma_rmb();
			return 0;
		}
		usleep_range(20, 50);
	} while (time_before(jiffies, deadline));

	pr_warn("knod: queues did not park\n");
	WRITE_ONCE(mem->control.pause, 0);
	g->park_value = 0;
	return -ETIMEDOUT;
}
EXPORT_SYMBOL(knod_gda_park);

void knod_gda_unpark(struct knod *knod)
{
	struct knod_gda *g = knod->gda;

	if (!g->park_value)
		return;
	/* The host's writes land before the queues run again. */
	wmb();
	WRITE_ONCE(knod_gda_mem(g)->control.pause, 0);
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
 * shader's place: stop the shader, copy, and leave the worker to start it
 * again.  The engine keeps a pointer to @code, which has to stay until the
 * next install.
 */
int knod_gda_install(struct knod *knod, const void *code, u32 size,
		     u32 lds_bytes)
{
	struct knod_gda *g = knod->gda;
	int err;

	if (!code || !size ||
	    size > knod->kernels[0]->size - KNOD_GDA_ENTRY_OFFSET)
		return -E2BIG;

	err = knod_gda_pause(knod, KNOD_GDA_PAUSE_PROGRAM);
	if (err)
		return err;
	knod_gda_shader_stop(g, KNOD_GDA_STOP_PROGRAM);
	g->code = code;
	g->code_size = size;
	g->lds_bytes = lds_bytes;
	g->code_is_default = false;
	knod_gda_copy_code(g);
	WRITE_ONCE(g->kernel_fault, false);
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
	err = knod_gda_install(knod, code, size, 0);
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
}
EXPORT_SYMBOL(knod_gda_set_client);

static int knod_gda_worker(void *arg)
{
	struct knod_gda *g = arg;
	u64 request;
	bool pause;

	while (!kthread_should_stop()) {
		mutex_lock(&g->client_lock);
		if (g->client && g->client->tick)
			g->client->tick(g->client_ctx);
		mutex_unlock(&g->client_lock);

		/* The program's clock: no packet carries one here. */
		WRITE_ONCE(((struct knod_bpf_param *)g->param->kaddr)->ktime_ns,
			   ktime_get_ns());

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

		knod_gda_pass_poll(g);
		usleep_range(100, 200);
	}
	return 0;
}

static void knod_gda_stop_worker(struct knod_gda *g)
{
	struct task_struct *task;

	task = xchg(&g->worker, NULL);
	if (task) {
		wake_up_all(&g->op_wq);
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

	knod_gda_stop_worker(g);
	knod_gda_shader_stop(g, KNOD_GDA_STOP_SHUTDOWN);
	pr_info("knod: %d queues, %u waves each\n", g->nr_queues, g->waves);

	knod_gda_copy_code(g);
	knod_gda_map_doorbells(g);
	knod_gda_control_init(g);
	knod_gda_shader_start(g);

	p = kthread_run(knod_gda_worker, g, "knod_%d_0", knod->accel->id);
	if (IS_ERR(p)) {
		pr_err("knod: no worker: %ld\n", PTR_ERR(p));
		knod_gda_shader_stop(g, KNOD_GDA_STOP_SHUTDOWN);
		return;
	}
	get_task_struct(p);
	WRITE_ONCE(g->worker, p);
}

/* Interface down: the shader leaves the rings where they stand, for the
 * next one to pick up.
 */
void knod_gda_stop(struct knod *knod)
{
	struct knod_gda *g = knod->gda;

	knod_gda_stop_worker(g);
	knod_gda_shader_stop(g, KNOD_GDA_STOP_SHUTDOWN);
}

static int knod_gda_stats_show(struct seq_file *s, void *unused)
{
	struct knod_gda *g = s->private;
	struct knod_persistent_mem *pm = knod_gda_mem(g);
	u64 pkts = 0, tx = 0, full = 0, rounds = 0, pass = 0, passed = 0;
	int q;

	for (q = 0; q < g->nr_queues; q++) {
		pkts += READ_ONCE(pm->control.gda[q].packets);
		rounds += READ_ONCE(pm->control.gda[q].rounds);
		pass += READ_ONCE(pm->control.gda[q].pass_pc);
		passed += READ_ONCE(pm->control.gda[q].pass_cc);
		tx += READ_ONCE(pm->control.gda[q].tx_packets);
		full += READ_ONCE(pm->control.gda[q].tx_full);
	}
	seq_printf(s, "queues:              %d\n", g->nr_queues);
	seq_printf(s, "workgroup_size:      %u\n", g->wg_size);
	seq_printf(s, "waves:               %u per queue\n", g->waves);
	seq_printf(s, "stagger:             %u\n", knod_gda_stagger);
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
	seq_printf(s, "pause_requests:      %llu\n", g->pause_requests);
	seq_printf(s, "pause_acks:          %llu\n", g->pause_acks);
	seq_printf(s, "pause_program:       %llu\n",
		   g->pause_reasons[KNOD_GDA_PAUSE_PROGRAM]);
	seq_printf(s, "pause_host_map:      %llu\n",
		   g->pause_reasons[KNOD_GDA_PAUSE_HOST_MAP]);
	seq_printf(s, "pause_map_gc:        %llu\n",
		   g->pause_reasons[KNOD_GDA_PAUSE_MAP_GC]);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(knod_gda_stats);

/*
 * Feature select: the engine's accel memory, and the rings offered to the NIC.
 * The receive kernel is what runs until something installs other code.
 */
int knod_gda_activate(struct knod *knod)
{
	struct knod_dev *knodev = knod->accel->knodev;
	struct knod_gda *g;
	u32 wg_size = knod_gda_workgroups;
	int err;

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
	g->wg_size = wg_size;
	g->waves = wg_size / 64;
	g->nr_queues = knod_gda_active_rxq_count(knodev->netdev);
	mutex_init(&g->op_lock);
	mutex_init(&g->client_lock);
	init_waitqueue_head(&g->op_wq);
	/* Never looked at, so the first shader start logs every queue. */
	memset(g->db_phys, 0xff, sizeof(g->db_phys));

	err = -EOPNOTSUPP;
	if (!g->nr_queues || g->nr_queues > knod->cu_count) {
		pr_warn("knod: %d RX queues for %d CUs, one persistent workgroup each\n",
			g->nr_queues, knod->cu_count);
		goto err_free;
	}
	g->code = knod_gda_default_code(knod, &g->code_size);
	if (!g->code) {
		pr_warn("knod: core blob has no receive kernel\n");
		goto err_free;
	}
	g->code_is_default = true;

	err = -ENOMEM;
	g->control = knod_alloc_mem(knod, KNOD_PERSIST_BYTES,
				    KFD_IOC_ALLOC_MEM_FLAGS_GTT |
				    KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
				    KFD_IOC_ALLOC_MEM_FLAGS_COHERENT);
	if (IS_ERR_OR_NULL(g->control)) {
		g->control = NULL;
		goto err_free;
	}
	/* Shader starts keep the rings' state; this is where it begins clean. */
	memset(g->control->kaddr, 0, sizeof(struct knod_persistent_mem));

	knod->gda = g;
	err = knod_gda_rings_init(g);
	if (err) {
		pr_warn("knod: no accel memory for the NIC's rings: %d\n", err);
		knod_gda_deactivate(knod);
		return err;
	}
	knod_gda_write_descriptor(knod);
	if (knod->debug_dir)
		debugfs_create_file("gda", 0444, knod->debug_dir, g,
				    &knod_gda_stats_fops);
	return 0;

err_free:
	kfree(g);
	return err;
}

void knod_gda_deactivate(struct knod *knod)
{
	struct knod_gda *g = knod->gda;
	int i;

	if (!g)
		return;
	if (knod->debug_dir)
		debugfs_lookup_and_remove("gda", knod->debug_dir);
	knod_gda_stop(knod);
	/* The drain counts finished PASS copies into the control block. */
	for (i = 0; i < KNOD_SPSC_MAX; i++)
		WRITE_ONCE(g->knodev->wpriv[i].gda_pass_cc, NULL);
	synchronize_net();
	knod_gda_unmap_doorbells(g);
	knod_gda_rings_exit(g);
	if (g->control)
		knod_free_mem(knod, g->control);
	knod->gda = NULL;
	kfree(g);
}
