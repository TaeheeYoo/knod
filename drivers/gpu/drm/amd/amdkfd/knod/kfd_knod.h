/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 */

#ifndef KFD_KNOD_H_
#define KFD_KNOD_H_
#include <linux/kfd_ioctl.h>
#include <net/knod.h>
#include <linux/genalloc.h>
#include "kfd_hsa.h"
#include <linux/completion.h>

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
	struct knod_mem *scratch;
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

typedef int (*knod_worker_fn_t)(void *ctx);
typedef void (*knod_flush_fn_t)(void *ctx);

enum knod_feature {
	KNOD_FEATURE_NONE = 0,
	KNOD_FEATURE_BPF,
	KNOD_FEATURE_IPSEC,
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
	int igpu;
	int isa_version;
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
	/* Worker callback — one active worker at a time */
	enum knod_feature active_feature;
	knod_worker_fn_t worker_fn;
	knod_flush_fn_t flush_fn;
	void *worker_ctx;
	struct task_struct *worker;
};

struct knod_dispatch_params {
	u16 workgroup_size_x;
	u32 grid_size_x;
	u32 grid_size_y;
	u32 private_segment_size;
	u32 group_segment_size;
	u64 kernel_object;
	u64 kernarg_address;
};

static inline void
knod_setup_invalidate(struct knod *knod, int idx, int q_idx)
{
	struct hsa_kernel_dispatch_packet *dp = knod->kaql[q_idx].aql->kaddr;

	dp += idx;
	dp->header = HSA_PACKET_TYPE_INVALID << HSA_PACKET_HEADER_TYPE;
}

static inline void
knod_setup_dispatch(struct knod *knod, int idx,
		    const struct knod_dispatch_params *p, int q_idx)
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
	dp->completion_signal = knod->kaql[q_idx].queue_signal->gaddr;
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
knod_setup_header(struct knod *knod,
		  const struct knod_dispatch_params *p, int q_idx)
{
	struct amd_queue *amd_queue = (struct amd_queue *)knod->kaql[q_idx].amd_queue->kaddr;
	int curr_idx = knod->kaql[q_idx].idx;
	int next_idx = curr_idx + 1;
	u64 *ptr = knod->kaql[q_idx].doorbell;

	knod_setup_invalidate(knod, next_idx % knod->nr_aql_ring, q_idx);
	knod_setup_dispatch(knod, curr_idx % knod->nr_aql_ring, p, q_idx);
	WRITE_ONCE(amd_queue->write_dispatch_id, curr_idx);
	writeq(curr_idx, ptr);
	knod->kaql[q_idx].idx = next_idx;
}

#define KNOD_NR_AQL_DEFAULT   1
struct knod *knod_alloc_ctx(struct knod_dev *knodev, int queue_cnt, int id,
			    int channels);
void knod_release_ctx(struct knod *knod);
void knod_accel_xdp_register(struct knod_accel_xdp_ops *xdp_ops);
void knod_accel_xdp_unregister(void);
void knod_accel_ipsec_register(struct knod_accel_ipsec_ops *ipsec_ops);
void knod_accel_ipsec_unregister(void);
void knod_request_queue_cnt(int n);
struct knod_mem *knod_alloc_mem(struct knod *knod, size_t size, int flags);
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

int knod_gart_map(struct amdgpu_device *adev, u64 npages,
		  dma_addr_t *addr, u64 *gart_addr, u64 flags);
int knod_register_worker(struct knod *knod, knod_worker_fn_t fn,
			 knod_flush_fn_t flush, void *ctx);
void knod_unregister_worker(struct knod *knod);
int knod_wait_on_events(struct kfd_process *p, u32 num_events,
			void __user *data, bool all, u32 *user_timeout_ms,
			u32 *wait_result);

#endif /* KFD_KNOD_H_ */
