/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

#ifndef KFD_KNOD_H_
#define KFD_KNOD_H_
#include <linux/kfd_ioctl.h>
#include <uapi/linux/knod_blob.h>
#include <net/knod.h>
#include <linux/genalloc.h>
#include "kfd_hsa.h"
#include <linux/completion.h>
#include <linux/seq_file.h>

/*
 * knod_dbg() is a pr_debug(), so it is off by default and toggled with
 * dynamic debug; knod_err() always fires.
 */
#define knod_dbg(fmt, ...)						\
	pr_debug("knod %s:%d" fmt, __func__, __LINE__, ##__VA_ARGS__)
#define knod_err(fmt, ...)						\
	pr_err("knod %s:%d" fmt, __func__, __LINE__, ##__VA_ARGS__)

struct page_pool;

struct knod_mem {
	struct list_head list;
	struct kgd_mem *mem;
	void *kaddr;
	u32 flags;
	u32 size;
	u32 order;
	u64 gaddr;
};

union knod_aql_rsrc1 {
	struct {
#if defined(__LITTLE_ENDIAN)
		unsigned int base_address_hi : 16;
		unsigned int stride : 14;
		unsigned int cache_swizzle : 1;
		unsigned int swizzle_enable : 1;
#elif defined(__LITTLE_ENDIAN)
		unsigned int swizzle_enable : 1;
		unsigned int cache_swizzle : 1;
		unsigned int stride : 14;
		unsigned int base_address_hi : 16;
#endif
	};
};

struct knod_aql {
	struct knod_mem *aql;
	struct knod_mem *ctx;
	struct knod_mem *queue;
	struct knod_mem *eop;
	struct knod_mem *queue_signal;
	struct knod_mem *tba;
	struct knod_mem *tma;
	struct knod_mem *amd_queue;
	u64 *doorbell;
	int idx;
};

struct knod_sdma {
	struct knod_mem *sdma;
	struct knod_mem *queue;
	struct knod_mem *queue_signal;
	u64 *doorbell;
	int idx;
};

/* KFD event handle as knod tracks it: signal event id + its slot index. */
struct knod_event {
	u32 id;
	u32 slot;
};


enum knod_feature {
	KNOD_FEATURE_NONE = 0,
	KNOD_FEATURE_BPF,
	KNOD_FEATURE_IPSEC, /* reserved ABI value */
	KNOD_FEATURE_MAX,
};

/*
 * One accel per GPU: NIC:GPU is fixed 1:1 so a single NIC owns the whole
 * device. The accel id is just the DRM render index (stride 1). Pipeline
 * depth within the one accel is provided by KNOD_MAX_QUEUE_CNT HW queues,
 * unrelated to this stride.
 */
#define KNOD_MAX_AQL  1

/* Internal AQL/SDMA queue pairs per attached knod context. BPF can keep these
 * queues in flight independently while the public accel-id ABI remains stable.
 */
#define KNOD_MAX_QUEUE_CNT  32

#define NR_AQL_RING 16384
#define AQL_STRUCT_SIZE 128

/* Every knod shader is wave64; the wave32 paths are dead. */
#define KNOD_WAVE_LANES			64
/* Machine code built for this GPU somewhere other than here.  One file per
 * thing that wants some - the core's own kernel, the BPF JIT's routines - so
 * that a file arriving late or not at all is that consumer's problem and no
 * one else's.  Same container either way, so one reader serves them all.
 */
struct knod;

struct knod_blob {
	const struct knod_blob_hdr *hdr;
	const struct knod_blob_entry *entries;
	size_t size;
};

int knod_blob_load(struct knod *knod, struct knod_blob *blob, const char *what);
void knod_blob_free(struct knod_blob *blob);
const u32 *knod_blob_find(const struct knod_blob *blob, u32 kind,
			  u32 key_chunks, u32 *size);

/* For messages about a routine that is missing, where the number on its own
 * says nothing about which one.
 */
static inline const char *knod_blob_kind_name(u32 kind)
{
	static const char * const names[KNOD_BLOB_KIND_MAX] = {
		[KNOD_BLOB_LOOKUP_ARRAY]	 = "array lookup",
		[KNOD_BLOB_UPDATE_ARRAY]	 = "array update",
		[KNOD_BLOB_DELETE_ARRAY]	 = "array delete",
		[KNOD_BLOB_LOOKUP_PERCPU_ARRAY]	 = "percpu array lookup",
		[KNOD_BLOB_UPDATE_PERCPU_ARRAY]	 = "percpu array update",
		[KNOD_BLOB_DELETE_PERCPU_ARRAY]	 = "percpu array delete",
		[KNOD_BLOB_LOOKUP_HASH]		 = "hash lookup",
		[KNOD_BLOB_UPDATE_HASH]		 = "hash update",
		[KNOD_BLOB_DELETE_HASH]		 = "hash delete",
		[KNOD_BLOB_LOOKUP_PERCPU_HASH]	 = "percpu hash lookup",
		[KNOD_BLOB_UPDATE_PERCPU_HASH]	 = "percpu hash update",
		[KNOD_BLOB_DELETE_PERCPU_HASH]	 = "percpu hash delete",
		[KNOD_BLOB_PROLOGUE]		 = "prologue",
		[KNOD_BLOB_EPILOGUE]		 = "epilogue",
		[KNOD_BLOB_DEFAULT_KERNEL]	 = "default kernel",
		[KNOD_BLOB_PASS_KERNEL]		 = "pass kernel",
	};

	if (kind >= KNOD_BLOB_KIND_MAX || !names[kind])
		return "routine";

	return names[kind];
}

struct knod {
	struct list_head list;
	struct list_head active_list;

	struct gen_pool *pool;

	struct hsa_kernel_dispatch_packet *dp;
	pid_t umh_pid;
	struct task_struct *umh_task;
	u32 nr_aql_ring;
	/* AQLs */
	int queue_cnt;
	int sdma_cnt;
	int cu_count;
	u32 simd_per_cu;
	u32 max_waves_per_simd;
	u32 vgpr_size_per_cu;
	/* LDS a workgroup can have, in bytes, as the topology reports it. */
	u32 lds_size;
	int igpu;
	int isa_version;
	/* maj * 10000 + min * 100 + step, which is how LLVM spells a target:
	 * 100300 is gfx1030.  Only the debugfs dumps use it, so that what they
	 * print can be fed straight to a disassembler.
	 */
	u32 gfx_target_version;
	/* NAPIs */
	int channels;
	struct kfd_process *process;
	struct mm_struct *mm;
	struct kfd_node *dev;
	struct file *drm_file;
	void __iomem *doorbell_base;
	u64 reserved_addr;
	u64 limit_addr;
	struct mutex lock;
	struct hsa_event *event;
	struct knod_mem *kernels[2];	/* dispatch slots: [0] default/pass, [1] BPF alt */
	struct knod_mem *mailbox;
	/* packet data path buf */
	struct knod_mem **buf;
	/* GDA: per-channel XDP SQ WQE buffers the shader writes and the NIC
	 * reads over P2P.  Uncached, so a WQE is in memory when its store
	 * completes rather than in the GPU's L2 where the NIC cannot see it.
	 */
	struct knod_mem **txsq;
	/* GDA stage 2: per-channel receive rings the NIC fills and the shader
	 * polls and refills (KNOD_GDA_* layout).  Uncached, so the NIC's CQEs
	 * are what the shader reads and the shader's doorbell records are what
	 * the NIC reads.
	 */
	struct knod_mem **gda_rx;

	u32 signal_eid;
	u32 completion_eid;
	struct knod_aql kaql[NR_CPUS];
	struct knod_sdma sdma[NR_CPUS];
	struct knod_event aql_event[NR_CPUS];
	struct knod_event sdma_event[NR_CPUS];
	u32 aql_queue_id[NR_CPUS];
	u32 sdma_queue_id[NR_CPUS];
	u64 aql_doorbell_offset[NR_CPUS];
	u64 sdma_doorbell_offset[NR_CPUS];
	bool aql_queue_created[NR_CPUS];
	bool sdma_queue_created[NR_CPUS];
	struct kfd_event_data *event_data;
	struct knod_accel *accel;
	struct dentry *debug_dir;
	enum knod_feature active_feature;
	/* The GDA engine running the NIC's rings for this accel, for every
	 * feature: with no program it passes every packet.  NULL until
	 * activated.
	 */
	struct knod_gda *gda;
	bool feature_active;	/* the active feature's own state is up */
	/* The core blob, kept for the engine's receive kernel. */
	struct knod_blob core_blob;
};

/*
 * The GDA engine: a persistent shader, one workgroup per queue, that runs the
 * NIC's receive rings, its XDP SQ and the hand-off of packets to the host,
 * with whatever code is installed between the rings' prologue and epilogue -
 * the receive kernel, which passes everything, or a BPF program.  The core
 * runs it for every feature; the BPF feature installs its programs into it and
 * parks it to change maps.
 */

/* Every kernel the engine runs declares this many VGPRs: the blob's register
 * map, v0-v75, the ring state the engine keeps in v73-v75 at the top.
 */
#define KNOD_GDA_VGPR_COUNT	ALIGN(KNOD_BLOB_PRO_GDA_VREG + \
				      KNOD_BLOB_PRO_GDA_VREGS, 4)

enum knod_gda_stop_reason {
	KNOD_GDA_STOP_SHUTDOWN,
	KNOD_GDA_STOP_PROGRAM,
	KNOD_GDA_STOP_REASON_MAX,
};

enum knod_gda_pause_reason {
	KNOD_GDA_PAUSE_PROGRAM,
	KNOD_GDA_PAUSE_HOST_MAP,
	KNOD_GDA_PAUSE_MAP_GC,
	KNOD_GDA_PAUSE_REASON_MAX,
};

/* What a feature running code in the engine wants from its worker. */
struct knod_gda_client {
	/* Every loop of the worker, with nothing held: map GC and the like. */
	void (*tick)(void *ctx);
};

struct knod_gda {
	struct knod *knod;
	struct knod_dev *knodev;
	int nr_queues;
	u32 wg_size;			/* lanes in a queue's workgroup */
	u32 waves;			/* of them, the waves that take packets */

	struct knod_mem *control;	/* struct knod_persistent_mem */
	struct knod_mem *param;		/* struct knod_bpf_param, PASS rings */
	struct knod_mem *rx_dma[KNOD_SPSC_MAX];
	struct knod_mem *db_mem[KNOD_SPSC_MAX];
	u64 db_gaddr[KNOD_SPSC_MAX];
	phys_addr_t db_phys[KNOD_SPSC_MAX];
	u32 pass_seen[KNOD_SPSC_MAX];

	/* The code in the slot, and what it asks of the dispatch. */
	const void *code;
	u32 code_size;
	u32 lds_bytes;
	bool code_is_default;
	bool kernel_fault;		/* the slot's code is not what should run */

	bool running;
	u64 launches, stops;
	u64 stop_reasons[KNOD_GDA_STOP_REASON_MAX];
	u32 park_value, park_seq;

	struct task_struct *worker;
	struct mutex client_lock;	/* held across a tick */
	const struct knod_gda_client *client;
	void *client_ctx;

	/* Code and map changes: one at a time, with the queues parked. */
	struct mutex op_lock;
	wait_queue_head_t op_wq;
	bool pause_requested;
	u64 pause_request, pause_ack;
	u64 pause_requests, pause_acks;
	u64 pause_reasons[KNOD_GDA_PAUSE_REASON_MAX];
};

int knod_gda_install(struct knod *knod, const void *code, u32 size,
		     u32 lds_bytes);
int knod_gda_install_default(struct knod *knod);
void knod_gda_mark_fault(struct knod *knod);
int knod_gda_pause(struct knod *knod, enum knod_gda_pause_reason reason);
void knod_gda_resume(struct knod *knod);
void knod_gda_leave_paused(struct knod *knod);
bool knod_gda_op_trylock(struct knod *knod);
void knod_gda_op_unlock(struct knod *knod);
int knod_gda_park(struct knod *knod);
void knod_gda_unpark(struct knod *knod);
void knod_gda_set_client(struct knod *knod,
			 const struct knod_gda_client *client, void *ctx);

/* The core's side: feature select and interface up/down. */
int knod_gda_activate(struct knod *knod);
void knod_gda_deactivate(struct knod *knod);
void knod_gda_start(struct knod *knod);
void knod_gda_stop(struct knod *knod);

struct knod_dispatch_params {
	u16 workgroup_size_x;
	u32 grid_size_x;
	u32 grid_size_y;
	u32 private_segment_size;
	u32 group_segment_size;
	u64 kernel_object;
	u64 kernarg_address;
};

/* The header a shader dump opens with.  knod-disasm reads the target and the
 * layout from it, so a dump can be disassembled without being told either.
 *
 * "block" is nothing but dwords, so offsets are counted from the start.
 * "annotated" carries one instruction per line among text that says where each
 * came from, which is worth keeping - it is about the BPF program, not the ISA.
 */
static inline void knod_seq_dump_header(struct seq_file *s, struct knod *knod,
					const char *what, const char *format,
					u64 entry, int dwords, int wave)
{
	u32 v = knod->gfx_target_version;

	seq_printf(s, "# knod %s\n", what);
	seq_printf(s, "# mcpu gfx%u%u%u\n", v / 10000, (v / 100) % 100, v % 100);
	seq_printf(s, "# wave %d\n", wave);
	seq_printf(s, "# format %s\n", format);
	if (entry)
		seq_printf(s, "# entry 0x%llx\n", entry);
	if (dwords)
		seq_printf(s, "# dwords %d\n", dwords);
}

static inline void
knod_setup_invalidate(struct knod *knod, int idx, int q_idx)
{
	struct hsa_kernel_dispatch_packet *dp = knod->kaql[q_idx].aql->kaddr;

	dp += idx;
	dp->header = HSA_PACKET_TYPE_INVALID << HSA_PACKET_HEADER_TYPE;
}

static inline void
knod_setup_dispatch(struct knod *knod, int idx,
		    const struct knod_dispatch_params *p, int q_idx,
		    u64 completion_signal)
{
	struct hsa_kernel_dispatch_packet *dp = knod->kaql[q_idx].aql->kaddr;

	dp += idx;
	dp->setup = 2;
	dp->workgroup_size_x = p->workgroup_size_x;
	dp->workgroup_size_y = 1;
	dp->workgroup_size_z = 1;
	dp->grid_size_x = p->grid_size_x;
	dp->grid_size_y = p->grid_size_y;
	dp->grid_size_z = 1;
	dp->private_segment_size = p->private_segment_size;
	dp->group_segment_size = p->group_segment_size;
	dp->kernel_object = p->kernel_object;
	dp->kernarg_address = (void *)p->kernarg_address;
	dp->completion_signal = completion_signal;
	/* publish the packet body before the valid header (WRITE_ONCE below) */
	wmb();
	WRITE_ONCE(dp->header,
		   (HSA_PACKET_TYPE_KERNEL_DISPATCH <<
		    HSA_PACKET_HEADER_TYPE) |
		   (HSA_FENCE_SCOPE_SYSTEM <<
		    HSA_PACKET_HEADER_ACQUIRE_FENCE_SCOPE) |
		   (HSA_FENCE_SCOPE_SYSTEM <<
		    HSA_PACKET_HEADER_RELEASE_FENCE_SCOPE));
}

static inline void
knod_setup_header_signal(struct knod *knod,
			 const struct knod_dispatch_params *p, int q_idx,
			 u64 completion_signal)
{
	struct amd_queue *amd_queue = (struct amd_queue *)knod->kaql[q_idx].amd_queue->kaddr;
	int curr_idx = knod->kaql[q_idx].idx;
	int next_idx = curr_idx + 1;
	u64 *ptr = knod->kaql[q_idx].doorbell;

	knod_setup_invalidate(knod, next_idx % knod->nr_aql_ring, q_idx);
	knod_setup_dispatch(knod, curr_idx % knod->nr_aql_ring, p, q_idx,
			    completion_signal);
	WRITE_ONCE(amd_queue->write_dispatch_id, curr_idx);
	writeq(curr_idx, ptr);
	knod->kaql[q_idx].idx = next_idx;
}

static inline void
knod_setup_header(struct knod *knod,
		  const struct knod_dispatch_params *p, int q_idx)
{
	knod_setup_header_signal(knod, p, q_idx,
				 knod->kaql[q_idx].queue_signal->gaddr);
}

#define KNOD_NR_AQL_DEFAULT   1
struct knod *knod_alloc_ctx(struct knod_dev *knodev, int queue_cnt, int id,
			    int channels);
void knod_release_ctx(struct knod *knod);
void knod_accel_xdp_register(struct knod_accel_xdp_ops *xdp_ops);
void knod_accel_xdp_unregister(void);
void knod_request_queue_cnt(int n);
/* The NIC's largest XDP SQ: 2^13 WQE basic blocks of 64 bytes. */
#define KNOD_TXSQ_BYTES		(64 << 13)

struct knod_mem *knod_alloc_mem(struct knod *knod, size_t size, int flags);
struct knod_mem *knod_map_mmio(struct knod *knod, phys_addr_t bus_addr,
			       size_t size);
struct knod_mem *__knod_alloc_mem(struct knod *knod, size_t size, int flags);
int __knod_map_mem(struct knod *knod, struct knod_mem *mem);
int __knod_export_dma_buf(struct knod *knod, struct knod_mem *mem);
int __knod_map_kaddr(struct knod *knod, struct knod_mem *mem);
void knod_free_mem(struct knod *pknod, struct knod_mem *mem);
void knod_sdma_copy(struct knod *knod, u64 dst_gart_addr, u64 src_gart_addr,
		    int idx, int size);
void knod_sdma_fence(struct knod *knod, u64 fence_addr, u32 fence_val,
		     int idx);
void knod_sdma_trap(struct knod *knod, int idx);
void knod_sdma_doorbell(struct knod *knod, int idx);
int knod_sdma_notify_u64(struct knod *knod, int idx, u64 addr,
			 u32 stride, u64 value, int n, u32 *fence);
int knod_sdma_wait_event(struct knod *knod, int idx, u32 timeout_ms,
			 bool *signaled);

/* One linear GPU->host SDMA copy (GPU VM addresses). */
struct knod_sdma_copy_desc {
	u64 dst;
	u64 src;
	u32 len;
};

/*
 * Emit @n copies on sdma[@idx] as one batch with ring backpressure.
 * Returns the post-batch ring position to fence/await, or 0 if the ring
 * is too full (caller drops the whole batch).  Pair with knod_sdma_kick().
 */
u32 knod_sdma_submit(struct knod *knod, int idx,
		     const struct knod_sdma_copy_desc *copies, int n);
void knod_sdma_kick(struct knod *knod, int idx);
u32 knod_sdma_gl2_maintain(struct knod *knod, int idx,
			   struct knod_mem *const *mems, int n,
			   bool writeback);
int knod_sdma_wait(struct knod *knod, int idx, u32 fence, u32 timeout_us);

int knod_gart_map(struct amdgpu_device *adev, u64 npages,
		  dma_addr_t *addr, u64 *gart_addr, u64 flags);

#endif /* KFD_KNOD_H_ */
