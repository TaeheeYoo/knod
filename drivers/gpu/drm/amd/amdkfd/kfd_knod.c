// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 * Copyright (c) 2021 Hoyeon Lee <hoyeon.rhee@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/dma-buf.h>
#include <crypto/algapi.h>
#include <crypto/internal/simd.h>
#include "kfd_priv.h"
#include "kfd_hsa.h"
#include "kfd_knod.h"
#include "kfd_topology.h"
#include "kfd_device_queue_manager.h"
#include "kfd_events.h"
#include <crypto/skcipher.h>
#include <crypto/internal/skcipher.h>
#include <linux/pid.h>
#include <linux/debugfs.h>
#include <linux/sched/signal.h>
#include "../amdgpu/amdgpu_amdkfd.h"
#include "../amdgpu/amdgpu_gfx.h"
#include "../amdgpu/./navi10_sdma_pkt_open.h"
#include "amdgpu_dpm.h"
#include "kgd_pp_interface.h"
#include <linux/kthread.h>
#include <linux/delay.h>
#include <drm/ttm/ttm_tt.h>
#include <linux/seq_file.h>
#include "knod_bpf.h"
#include <net/page_pool/helpers.h>
#include <linux/netdevice.h>

struct umh_data {
	pid_t pid;
};

LIST_HEAD(ctx_list);

/*
 * AQL/SDMA queue pair count requested by the highest-demand accel
 * consumer (currently knod_ipsec's parallel-dispatcher machinery).
 * Each accel module sets this via knod_request_queue_cnt() during its
 * module_init BEFORE the NOD attach happens, so knod_attach() creates
 * a context with enough kaql[]/sdma[] pairs for the worst-case
 * consumer.
 *
 * The value is a high-water mark across all accel types - whichever
 * consumer asks for the most queue pairs wins; a consumer that needs
 * fewer just leaves the extra pairs unused (a minor, harmless GPU
 * resource waste).
 *
 * Default is 1 when nothing has called the setter - mirrors the
 * historical single-queue behaviour.
 */
static int knod_requested_queue_cnt = 1;

static struct knod_accel *accels[KNOD_MAX_AQL];
static int nr_accels;
static struct knod_accel_ops accel_ops;

/*
 * Thin wrappers around the KFD core entry points.  knod drives KFD from
 * kernel context using kernel-internal types, so it calls these directly
 * instead of going through the kfd_ioctl_* handlers (which marshal user
 * data and stay static to KFD).
 */
static int knod_create_queue(struct kfd_process *p,
			     struct queue_properties *qp, u32 gpu_id,
			     u32 *queue_id, u64 *doorbell_offset)
{
	return kfd_create_queue(p, qp, gpu_id, queue_id, doorbell_offset);
}

static int knod_destroy_queue(struct kfd_process *p, u32 queue_id)
{
	int ret;

	mutex_lock(&p->mutex);
	ret = pqm_destroy_queue(&p->pqm, queue_id);
	mutex_unlock(&p->mutex);
	return ret;
}

static int knod_create_event(struct kfd_process *p, u32 event_type,
			     bool auto_reset, u32 node_id,
			     struct knod_event *event)
{
	u32 event_trigger_data;
	u64 event_page_offset = 0;

	return kfd_event_create(NULL, p, event_type, auto_reset, node_id,
				&event->id, &event_trigger_data,
				&event_page_offset, &event->slot);
}

static int knod_destroy_event(struct kfd_process *p, u32 event_id)
{
	return kfd_event_destroy(p, event_id);
}

struct knod_mem *__knod_alloc_mem(struct knod *knod, size_t size,
				  int flags)
{
	struct kfd_process_device *pdd = knod->process->pdds[0];
	struct kfd_node *kdev = pdd->dev;
	struct knod_mem *mem;
	int err;

	mem = kzalloc_obj(struct knod_mem, GFP_KERNEL);
	if (!mem)
		return ERR_PTR(-ENOMEM);

	size = ALIGN(size, PAGE_SIZE);
	mem->flags = flags;
	mem->size = size;
	mem->gaddr = gen_pool_alloc(knod->pool, size);
	if (!mem->gaddr) {
		kfree(mem);
		return ERR_PTR(-ENOMEM);
	}

	err = amdgpu_amdkfd_gpuvm_alloc_memory_of_gpu(kdev->adev, mem->gaddr,
						      size, pdd->drm_priv,
						      &mem->mem, NULL, flags,
						      false);
	if (err) {
		knod_err(" failed to alloc mem\n");
		gen_pool_free(knod->pool, mem->gaddr, mem->size);
		kfree(mem);
		return ERR_PTR(-ENOMEM);
	}

	err = amdgpu_amdkfd_gpuvm_sync_memory(kdev->adev, mem->mem, true);
	if (err) {
		pr_debug("Sync memory failed, wait interrupted by user signal\n");
		amdgpu_amdkfd_gpuvm_free_memory_of_gpu(kdev->adev, mem->mem,
						       pdd->drm_priv, NULL);
		gen_pool_free(knod->pool, mem->gaddr, mem->size);
		kfree(mem);
		return ERR_PTR(-ENOMEM);
	}

	list_add_tail(&mem->list, &knod->active_list);

	return mem;
}

int __knod_export_dma_buf(struct knod *knod, struct knod_mem *mem)
{
	struct dma_buf *dmabuf;
	int err;

	err = amdgpu_amdkfd_gpuvm_export_dmabuf(mem->mem, &dmabuf);
	if (err) {
		pr_debug("export dmabuf failed\n");
		return -ENOMEM;
	}

	dma_buf_put(dmabuf);

	return 0;
}

struct knod_mem *knod_alloc_mem(struct knod *knod, size_t size, int flags)
{
	struct knod_mem *mem;
	int err;

	mem = kzalloc_obj(struct knod_mem, GFP_KERNEL);
	if (!mem)
		return ERR_PTR(-ENOMEM);

	size = ALIGN(size, PAGE_SIZE);
	mem->flags = flags;
	mem->size = size;
	mem->gaddr = gen_pool_alloc(knod->pool, size);
	if (!mem->gaddr) {
		kfree(mem);
		return ERR_PTR(-ENOMEM);
	}

	err = kfd_process_alloc_gpuvm(knod->process->pdds[0],
				      mem->gaddr,
				      mem->size,
				      flags,
				      &mem->mem,
				      &mem->kaddr);

	if (err) {
		knod_err(" err = %d\n", err);
		gen_pool_free(knod->pool, mem->gaddr, mem->size);
		kfree(mem);
		return ERR_PTR(-ENOMEM);
	}

	list_add_tail(&mem->list, &knod->active_list);

	return mem;
}
EXPORT_SYMBOL(knod_alloc_mem);

int __knod_map_kaddr(struct knod *knod, struct knod_mem *mem)
{
	int err = 0;

	if (mem->flags & KFD_IOC_ALLOC_MEM_FLAGS_GTT) {
		err = amdgpu_amdkfd_gpuvm_map_gtt_bo_to_kernel(mem->mem,
							       &mem->kaddr,
							       NULL);
		if (err) {
			pr_debug("Map GTT BO to kernel failed\n");
			err = -ENOMEM;
		}
	} else if (mem->flags & KFD_IOC_ALLOC_MEM_FLAGS_VRAM) {
		err = amdgpu_amdkfd_gpuvm_map_vram_bo_to_kernel(mem->mem,
								&mem->kaddr,
								NULL);
		if (err) {
			pr_debug("Map VRAM BO to kernel failed\n");
			err = -ENOMEM;
		}
	}

	return err;
}

int __knod_map_mem(struct knod *knod, struct knod_mem *mem)
{
	struct kfd_process_device *pdd = knod->process->pdds[0];
	struct kfd_node *kdev = pdd->dev;
	int err;

	err = amdgpu_amdkfd_gpuvm_map_memory_to_gpu(kdev->adev, mem->mem,
						    pdd->drm_priv);
	if (err) {
		knod_err(" failed to map gpu\n");
		return 1;
	}

	err = amdgpu_amdkfd_gpuvm_sync_memory(kdev->adev, mem->mem, true);
	if (err) {
		pr_debug("Sync memory failed, wait interrupted by user signal\n");
		return 1;
	}

	return 0;
}
EXPORT_SYMBOL(__knod_map_mem);

void knod_free_mem(struct knod *knod, struct knod_mem *mem)
{
	if (mem) {
		list_del_init(&mem->list);
		kfd_process_free_gpuvm(mem->mem, knod->process->pdds[0],
				       &mem->kaddr);
		gen_pool_free(knod->pool, mem->gaddr, mem->size);
		kfree(mem);
	}
}
EXPORT_SYMBOL(knod_free_mem);

void knod_sdma_copy(struct knod *knod, u64 dst_offset,
		    u64 src_offset, int idx, int size)
{
	struct knod_sdma *sdma = &knod->sdma[idx];
	u32 ring_mask = (sdma->sdma->size / 4) - 1;
	u64 *wptr = (u64 *)sdma->queue->kaddr + 1;
	u32 *ptr = sdma->sdma->kaddr;

	ptr[sdma->idx++ & ring_mask] = SDMA_PKT_HEADER_OP(SDMA_OP_COPY) |
		SDMA_PKT_HEADER_SUB_OP(SDMA_SUBOP_COPY_LINEAR) |
		SDMA_PKT_COPY_LINEAR_HEADER_TMZ((0));
	ptr[sdma->idx++ & ring_mask] = size - 1;
	ptr[sdma->idx++ & ring_mask] = 0; /* src/dst endian swap */
	ptr[sdma->idx++ & ring_mask] = lower_32_bits(src_offset);
	ptr[sdma->idx++ & ring_mask] = upper_32_bits(src_offset);
	ptr[sdma->idx++ & ring_mask] = lower_32_bits(dst_offset);
	ptr[sdma->idx++ & ring_mask] = upper_32_bits(dst_offset);

	*wptr += 7 * 4;
}

void knod_sdma_fence(struct knod *knod, u64 fence_addr, u32 fence_val,
		     int idx)
{
	struct knod_sdma *sdma = &knod->sdma[idx];
	u32 ring_mask = (sdma->sdma->size / 4) - 1;
	u64 *wptr = (u64 *)sdma->queue->kaddr + 1;
	u32 *ptr = sdma->sdma->kaddr;
	u32 hdr = SDMA_PKT_HEADER_OP(SDMA_OP_FENCE);

	if (knod->isa_version >= 10)
		hdr |= SDMA_PKT_FENCE_HEADER_MTYPE(3);

	ptr[sdma->idx++ & ring_mask] = hdr;
	ptr[sdma->idx++ & ring_mask] = lower_32_bits(fence_addr);
	ptr[sdma->idx++ & ring_mask] = upper_32_bits(fence_addr);
	ptr[sdma->idx++ & ring_mask] = fence_val;

	*wptr += 4 * 4;
}

void knod_sdma_trap(struct knod *knod, int idx)
{
	struct knod_sdma *sdma = &knod->sdma[idx];
	u32 ring_mask = (sdma->sdma->size / 4) - 1;
	u64 *wptr = (u64 *)sdma->queue->kaddr + 1;
	u32 *ptr = sdma->sdma->kaddr;
	u32 ctx = knod->sdma_event[idx].id & 0x0fffffff;
	u64 slot_addr = knod->mailbox->gaddr +
		knod->sdma_event[idx].slot * 8;
	u32 hdr;

	/* Write 0 to the signal page slot so lookup_signaled_event
	 * sees it as non-UNSIGNALED (0xFFFFFFFFFFFFFFFF).
	 */
	hdr = SDMA_PKT_HEADER_OP(SDMA_OP_FENCE);
	if (knod->isa_version >= 10)
		hdr |= SDMA_PKT_FENCE_HEADER_MTYPE(3);

	ptr[sdma->idx++ & ring_mask] = hdr;
	ptr[sdma->idx++ & ring_mask] = lower_32_bits(slot_addr);
	ptr[sdma->idx++ & ring_mask] = upper_32_bits(slot_addr);
	ptr[sdma->idx++ & ring_mask] = 0;

	ptr[sdma->idx++ & ring_mask] = SDMA_PKT_HEADER_OP(SDMA_OP_TRAP);
	ptr[sdma->idx++ & ring_mask] = ctx;

	*wptr += 6 * 4;
}

void knod_sdma_doorbell(struct knod *knod, int idx)
{
	struct knod_sdma *sdma = &knod->sdma[idx];
	u64 *wptr = (u64 *)sdma->queue->kaddr + 1;

	/* ensure the SDMA ring writes are visible before ringing doorbell */
	wmb();
	writeq(*wptr, sdma->doorbell);
}

u32 knod_sdma_submit(struct knod *knod, int idx,
		     const struct knod_sdma_copy_desc *copies, int n)
{
	struct knod_sdma *sdma = &knod->sdma[idx];
	u32 capacity = sdma->sdma->size / 4;
	u32 completed, inflight;
	int i;

	/*
	 * knod_sdma_copy has no overflow guard (sdma->idx is the dword write
	 * cursor that just wraps), so drop the whole batch once the ring is
	 * near full.  @completed is the last fenced cursor (knod_sdma_kick
	 * writes sdma->idx into the signal), so @inflight is the unprocessed
	 * span; reserve room for these @n copies (7 dwords each) plus a fence.
	 * Signed compare so a stale signal ahead of the cursor (e.g. at
	 * startup) reads as "negative" inflight rather than a false full.
	 */
	completed = (u32)READ_ONCE(((struct amd_signal *)
				    sdma->queue_signal->kaddr)->value);
	inflight = (u32)sdma->idx - completed;
	if ((s32)(inflight + n * 7) >= (s32)(capacity - 64))
		return 0;

	for (i = 0; i < n; i++)
		knod_sdma_copy(knod, copies[i].dst, copies[i].src, idx,
			       copies[i].len);

	return (u32)sdma->idx;
}
EXPORT_SYMBOL(knod_sdma_submit);

void knod_sdma_kick(struct knod *knod, int idx)
{
	struct knod_sdma *sdma = &knod->sdma[idx];
	u64 fence_addr;

	fence_addr = sdma->queue_signal->gaddr +
		     offsetof(struct amd_signal, value);
	knod_sdma_fence(knod, fence_addr, (u32)sdma->idx, idx);
	knod_sdma_doorbell(knod, idx);
}
EXPORT_SYMBOL(knod_sdma_kick);

int knod_gart_map(struct amdgpu_device *adev, u64 npages,
		  dma_addr_t *addr, u64 *gart_addr, u64 flags)
{
	struct amdgpu_ring *ring =
		to_amdgpu_ring(adev->mman.buffer_funcs_scheds[0]);
	struct amdgpu_job *job;
	unsigned int num_dw, num_bytes;
	struct dma_fence *fence;
	u64 src_addr, dst_addr;
	u64 pte_flags;
	void *cpu_addr;
	int r;

	/* use gart window 0 */
	*gart_addr = adev->gmc.gart_start;

	num_dw = ALIGN(adev->mman.buffer_funcs->copy_num_dw, 8);
	num_bytes = npages * 8;

	r = amdgpu_job_alloc_with_ib(adev, &adev->mman.default_entity.base,
				     AMDGPU_FENCE_OWNER_UNDEFINED,
				     num_dw * 4 + num_bytes,
				     AMDGPU_IB_POOL_DELAYED,
				     &job,
				     AMDGPU_KERNEL_JOB_ID_TTM_MAP_BUFFER);
	if (r)
		return r;

	src_addr = num_dw * 4;
	src_addr += job->ibs[0].gpu_addr;

	dst_addr = amdgpu_bo_gpu_offset(adev->gart.bo);
	amdgpu_emit_copy_buffer(adev, &job->ibs[0], src_addr,
				dst_addr, num_bytes, 0);

	amdgpu_ring_pad_ib(ring, &job->ibs[0]);
	WARN_ON(job->ibs[0].length_dw > num_dw);

	pte_flags = AMDGPU_PTE_VALID | AMDGPU_PTE_READABLE;
	pte_flags |= AMDGPU_PTE_SYSTEM | AMDGPU_PTE_SNOOPED;
	if (!(flags & KFD_IOCTL_SVM_FLAG_GPU_RO))
		pte_flags |= AMDGPU_PTE_WRITEABLE;
	pte_flags |= adev->gart.gart_pte_flags;

	cpu_addr = &job->ibs[0].ptr[num_dw];

	amdgpu_gart_map(adev, 0, npages, addr, pte_flags, cpu_addr);
	fence = amdgpu_job_submit(job);
	dma_fence_put(fence);

	return r;
}

static void knod_init_aql_queue(struct knod *knod, int qid, int idx)
{
	struct amd_queue *amd_queue =
		(struct amd_queue *)knod->kaql[idx].queue->kaddr;
	union knod_aql_rsrc1 rsrc1;
	u32 scratch_gaddr;
	int i;

	for (i = 0; i < knod->nr_aql_ring; i++)
		knod_setup_invalidate(knod, i, idx);

	amd_queue->hsa_queue.type = HSA_QUEUE_TYPE_MULTI;
	amd_queue->hsa_queue.features = HSA_QUEUE_FEATURE_KERNEL_DISPATCH;
	amd_queue->hsa_queue.base_address = (void *)knod->kaql[idx].aql->gaddr;
	amd_queue->hsa_queue.doorbell_signal =
		knod->kaql[idx].queue_signal->gaddr;
	amd_queue->hsa_queue.size = knod->nr_aql_ring;
	amd_queue->hsa_queue.reserved1 = 0;
	amd_queue->hsa_queue.id = qid;

	amd_queue->write_dispatch_id = 0; /* id is index */
	amd_queue->group_segment_aperture_base_hi = 0;
	amd_queue->private_segment_aperture_base_hi = 0;
	amd_queue->max_cu_id = -1;
	amd_queue->max_wave_id = -1;
	amd_queue->max_legacy_doorbell_dispatch_id_plus_1 = 0;
	amd_queue->legacy_doorbell_lock = 0;
	amd_queue->read_dispatch_id = 0; /* id is index */
	amd_queue->read_dispatch_id_field_base_byte_offset = 0x80;
	/* scratch resource descriptor - use allocated scratch BO address */
	scratch_gaddr = (u32)(knod->kaql[idx].scratch->gaddr & 0xffffffff);
	amd_queue->scratch_resource_descriptor[0] = scratch_gaddr;
	scratch_gaddr = (u32)((knod->kaql[idx].scratch->gaddr >> 32) & 0xffff);
	rsrc1.base_address_hi = scratch_gaddr;
	rsrc1.stride = 0;
	rsrc1.cache_swizzle = 0;
	rsrc1.swizzle_enable = 1;
	memcpy(&amd_queue->scratch_resource_descriptor[1], &rsrc1, sizeof(u32));
	amd_queue->scratch_resource_descriptor[2] =
		knod->kaql[idx].scratch->size;
	amd_queue->scratch_resource_descriptor[3] = 0x00ffffff;
	amd_queue->scratch_backing_memory_location =
		knod->kaql[idx].scratch->gaddr;
	amd_queue->scratch_backing_memory_byte_size =
		knod->kaql[idx].scratch->size;
	amd_queue->scratch_wave64_lane_byte_size = 64;

	amd_queue->queue_properties.is_ptr64 = 1;
	amd_queue->queue_properties.enable_trap_handler_debug_sgprs = 0;
}

static void knod_init_sdma_queue(struct knod *knod, int qid, int idx)
{
}

static void knod_init_queue(struct knod *knod, int qid, int idx, int type)
{
	if (type == KFD_IOC_QUEUE_TYPE_COMPUTE_AQL)
		knod_init_aql_queue(knod, qid, idx);
	else if (type == KFD_IOC_QUEUE_TYPE_SDMA)
		knod_init_sdma_queue(knod, qid, idx);
}

static void stop_umh(pid_t umh_pid)
{
	struct pid *p = find_get_pid(umh_pid);

	if (!p)
		return;

	kill_pid(p, SIGKILL, 1);
	put_pid(p);
}

static int umh_init(struct subprocess_info *info, struct cred *new)
{
	struct umh_data *d = info->data;

	d->pid = current->pid;

	return 0;
}

static int launch_and_get_pid(void)
{
	static const char * const argv[] = { "/bin/sleep", "2147483647", NULL };
	static const char * const envp[] = { "HOME=/", "PATH=/sbin:/bin", NULL };
	struct umh_data data = { .pid = -1 };
	struct subprocess_info *info;
	int ret;

	info = call_usermodehelper_setup(argv[0], (char **)argv,
					 (char **)envp, GFP_KERNEL,
					 umh_init, NULL, &data);
	if (!info) {
		pr_err("UMH setup failed\n");
		return 0;
	}

	ret = call_usermodehelper_exec(info, UMH_WAIT_EXEC);
	if (ret < 0) {
		pr_err("UMH exec failed: %d\n", ret);
		return 0;
	}

	return data.pid;
}

static int knod_set_isa(struct knod *knod)
{
	enum amd_asic_type asic_type;

	asic_type = knod->process->pdds[0]->dev->adev->asic_type;
	if (knod->isa_version != 9 && knod->isa_version != 10)
		knod->isa_version = 0;
	if (knod->isa_version == 0) {
		if (asic_type <= CHIP_VEGAM) {
			pr_err("Not supported chip");
			return -EOPNOTSUPP;
		} else if (asic_type == CHIP_VEGA10 ||
				asic_type == CHIP_VEGA12 ||
				asic_type == CHIP_VEGA20 ||
				asic_type == CHIP_RAVEN ||
				asic_type == CHIP_RENOIR) {
			pr_debug("GCN5 is detected");
			knod->isa_version = 9;
		} else if (asic_type == CHIP_NAVI10 ||
				asic_type == CHIP_NAVI12 ||
				asic_type == CHIP_NAVI14 ||
				asic_type == CHIP_CYAN_SKILLFISH) {
			pr_err("RDNA1 is not supported yet");
			return -EOPNOTSUPP;
		} else if (asic_type == CHIP_SIENNA_CICHLID ||
				asic_type == CHIP_NAVY_FLOUNDER ||
				asic_type == CHIP_DIMGREY_CAVEFISH ||
				asic_type == CHIP_BEIGE_GOBY ||
				asic_type == CHIP_YELLOW_CARP) {
			pr_debug("RDNA2 is detected");
			knod->isa_version = 10;
		} else if (asic_type == CHIP_ARCTURUS ||
				asic_type == CHIP_ALDEBARAN) {
			pr_err("CDNA is not supported yet");
			return -EOPNOTSUPP;
		} else if (asic_type == CHIP_IP_DISCOVERY) {
			pr_err("Can't detect chip version, firmware update may be needed");
			return -EOPNOTSUPP;
		} else {
			pr_err("Not supported chip");
			return -EOPNOTSUPP;
		}
	}

	knod->igpu = false;
	if (asic_type == CHIP_RENOIR || asic_type == CHIP_RAVEN ||
	    asic_type == CHIP_CYAN_SKILLFISH || asic_type == CHIP_BEIGE_GOBY ||
	    asic_type == CHIP_YELLOW_CARP) {
		pr_debug("iGPU is detected");
		knod->igpu = true;
	}

	return 0;
}

static void knod_destroy_one_queue(struct knod *knod, int idx)
{
	/* Destroy queue and event BEFORE freeing BOs.
	 * Queue holds references to BO VAs; freeing BOs first causes
	 * NULL deref in kfd_queue_unref_bo_vas when UMH exits.
	 * Use the created flag (not queue_id value) since KFD IDR can
	 * assign queue_id=0 to the first queue.
	 */
	if (knod->aql_queue_created[idx]) {
		int ret;

		ret = knod_destroy_queue(knod->process,
					 knod->aql_queue_id[idx]);
		if (ret)
			pr_err("knod: destroy_queue failed: %d (queue_id=%u)\n",
			       ret, knod->aql_queue_id[idx]);
		knod->aql_queue_created[idx] = false;
		knod->aql_queue_id[idx] = 0;
	}
	if (knod->aql_event[idx].id) {
		knod_destroy_event(knod->process, knod->aql_event[idx].id);
		knod->aql_event[idx].id = 0;
	}

	knod_free_mem(knod, knod->kaql[idx].aql);
	knod_free_mem(knod, knod->kaql[idx].queue);
	knod_free_mem(knod, knod->kaql[idx].eop);
	knod_free_mem(knod, knod->kaql[idx].ctx);
	knod_free_mem(knod, knod->kaql[idx].queue_signal);
	knod_free_mem(knod, knod->kaql[idx].amd_queue);
	knod_free_mem(knod, knod->kaql[idx].scratch);
}

static int knod_alloc_one_queue(struct knod *knod, int idx,
				struct kfd_topology_device *topo_dev,
				struct kfd_process_device *pdd, void *ptr)
{
	int buf_flags = KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
			KFD_IOC_ALLOC_MEM_FLAGS_COHERENT |
			KFD_IOC_ALLOC_MEM_FLAGS_VRAM;
	int flags = KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE |
		    KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
		    KFD_IOC_ALLOC_MEM_FLAGS_COHERENT |
		    KFD_IOC_ALLOC_MEM_FLAGS_GTT;
	struct amd_signal *queue_signal;
	struct amd_queue *amd_queue;
	struct queue_properties qp;
	u32 total_cwsr_size;
	int err;

	knod->kaql[idx].aql = knod_alloc_mem(knod,
		(NR_AQL_RING *
		 sizeof(struct hsa_kernel_dispatch_packet) * 2),
		KFD_IOC_ALLOC_MEM_FLAGS_GTT |
		KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
		KFD_IOC_ALLOC_MEM_FLAGS_COHERENT |
		KFD_IOC_ALLOC_MEM_FLAGS_UNCACHED |
		KFD_IOC_ALLOC_MEM_FLAGS_AQL_QUEUE_MEM |
		KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE);
	if (IS_ERR(knod->kaql[idx].aql)) {
		err = PTR_ERR(knod->kaql[idx].aql);
		knod->kaql[idx].aql = NULL;
		goto err_mem;
	}

	knod->kaql[idx].queue = knod_alloc_mem(knod, PAGE_SIZE, flags);
	if (IS_ERR(knod->kaql[idx].queue)) {
		err = PTR_ERR(knod->kaql[idx].queue);
		knod->kaql[idx].queue = NULL;
		goto err_mem;
	}

	knod->kaql[idx].eop = knod_alloc_mem(knod, PAGE_SIZE, flags);
	if (IS_ERR(knod->kaql[idx].eop)) {
		err = PTR_ERR(knod->kaql[idx].eop);
		knod->kaql[idx].eop = NULL;
		goto err_mem;
	}

	total_cwsr_size = (topo_dev->node_props.cwsr_size +
			   topo_dev->node_props.debug_memory_size)
			  * NUM_XCC(pdd->dev->xcc_mask);
	total_cwsr_size = ALIGN(total_cwsr_size, PAGE_SIZE);

	knod->kaql[idx].ctx = knod_alloc_mem(knod, total_cwsr_size, buf_flags);
	if (IS_ERR(knod->kaql[idx].ctx)) {
		err = PTR_ERR(knod->kaql[idx].ctx);
		knod->kaql[idx].ctx = NULL;
		goto err_mem;
	}

	knod->kaql[idx].queue_signal = knod_alloc_mem(knod,
		PAGE_SIZE << 5,
		KFD_IOC_ALLOC_MEM_FLAGS_GTT |
		KFD_IOC_ALLOC_MEM_FLAGS_COHERENT |
		KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE |
		KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE);
	if (IS_ERR(knod->kaql[idx].queue_signal)) {
		err = PTR_ERR(knod->kaql[idx].queue_signal);
		knod->kaql[idx].queue_signal = NULL;
		goto err_mem;
	}

	knod->kaql[idx].amd_queue = knod_alloc_mem(knod,
		PAGE_SIZE << 5,
		KFD_IOC_ALLOC_MEM_FLAGS_GTT |
		KFD_IOC_ALLOC_MEM_FLAGS_COHERENT);
	if (IS_ERR(knod->kaql[idx].amd_queue)) {
		err = PTR_ERR(knod->kaql[idx].amd_queue);
		knod->kaql[idx].amd_queue = NULL;
		goto err_mem;
	}

	knod->kaql[idx].scratch = knod_alloc_mem(knod,
		PAGE_SIZE << 5,
		KFD_IOC_ALLOC_MEM_FLAGS_VRAM |
		KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
		KFD_IOC_ALLOC_MEM_FLAGS_COHERENT);
	if (IS_ERR(knod->kaql[idx].scratch)) {
		err = PTR_ERR(knod->kaql[idx].scratch);
		knod->kaql[idx].scratch = NULL;
		goto err_mem;
	}

	knod->kaql[idx].idx = 0;

	/*
	 * KNOD dispatchers poll queue_signal->value directly. Do not attach a
	 * KFD signal event to every AQL completion; at high packet rates the
	 * unused event notifications overflow the KFD interrupt/event path and
	 * add latency without contributing to completion detection.
	 */
	knod->aql_event[idx].id = 0;
	knod->aql_event[idx].slot = 0;
	knod->signal_eid = 0;

	/* Zero ALL queue-related GPU memory BEFORE creating the HW queue.
	 * kfd_ioctl_create_queue loads HQD immediately - if the memory
	 * contains stale data from a previous session (write/read pointers,
	 * AQL dispatch packets, doorbell values), the GPU starts processing
	 * garbage packets and goes to 100%.
	 */
	memset(knod->kaql[idx].queue->kaddr, 0, knod->kaql[idx].queue->size);
	/* AQL ring is allocated 2x with AQL_QUEUE_MEM flag; the second
	 * half is a GPU-side mirror for wrap-around.  kaddr only covers
	 * the first half.
	 */
	memset(knod->kaql[idx].aql->kaddr, 0, knod->kaql[idx].aql->size / 2);
	memset(knod->kaql[idx].eop->kaddr, 0, knod->kaql[idx].eop->size);
	memset(knod->kaql[idx].amd_queue->kaddr, 0,
	       knod->kaql[idx].amd_queue->size);
	knod_init_queue(knod, idx, idx, KFD_IOC_QUEUE_TYPE_COMPUTE_AQL);

	memset(&qp, 0, sizeof(qp));
	qp.type = KFD_QUEUE_TYPE_COMPUTE;
	qp.format = KFD_QUEUE_FORMAT_AQL;
	qp.queue_percent = 100;
	qp.priority = 15;
	qp.ctl_stack_size = topo_dev->node_props.ctl_stack_size;
	qp.ctx_save_restore_area_size = topo_dev->node_props.cwsr_size;
	qp.ctx_save_restore_area_address = (u64)knod->kaql[idx].ctx->gaddr;
	qp.queue_address = (u64)knod->kaql[idx].aql->gaddr;
	qp.queue_size = knod->kaql[idx].aql->size / 2;
	qp.write_ptr =
		(void __user *)((u64)knod->kaql[idx].queue->gaddr + 0x38);
	qp.read_ptr = (void __user *)((u64)knod->kaql[idx].queue->gaddr + 0x80);
	qp.eop_ring_buffer_address = (u64)knod->kaql[idx].eop->gaddr;
	qp.eop_ring_buffer_size = knod->kaql[idx].eop->size;

	err = knod_create_event(knod->process, KFD_IOC_EVENT_SIGNAL, true, 1,
				&knod->aql_event[idx]);
	if (err) {
		knod_err(" failed to create AQL event[%d] err=%d\n", idx, err);
		goto err_mem;
	}

	queue_signal = (struct amd_signal *)knod->kaql[idx].queue_signal->kaddr;
	queue_signal->kind = AMD_SIGNAL_KIND_USER;
	if (queue_signal->kind == AMD_SIGNAL_KIND_DOORBELL) {
		queue_signal->value = 0;
		queue_signal->event_id = 0;
		queue_signal->queue_ptr = (void *)knod->kaql[idx].queue->gaddr;
		queue_signal->hardware_doorbell_ptr = ptr;
		queue_signal->event_mailbox_ptr = 0;
	} else if (queue_signal->kind == AMD_SIGNAL_KIND_USER) {
		queue_signal->event_id = knod->aql_event[idx].id;
		queue_signal->queue_ptr = 0;
		queue_signal->event_mailbox_ptr = knod->mailbox->gaddr +
			knod->aql_event[idx].slot * 8;
		/* value is in union with hardware_doorbell_ptr - set last */
		queue_signal->value = 0xffffffffffffffff;
	}
	knod_dbg(" pre-create-queue signal=%lld kaddr=%p gaddr=0x%llx\n",
		 READ_ONCE(queue_signal->value), queue_signal,
		 knod->kaql[idx].queue_signal->gaddr);

	err = knod_create_queue(knod->process, &qp, pdd->user_gpu_id,
				&knod->aql_queue_id[idx],
				&knod->aql_doorbell_offset[idx]);
	if (err) {
		knod_err(" failed to create queue, err = %d\n", err);
		goto err_mem;
	}
	knod->aql_queue_created[idx] = true;

	knod_dbg(" post-create-queue signal=%lld queue_id=%d\n",
		 READ_ONCE(queue_signal->value), knod->aql_queue_id[idx]);

	/* Update queue id with the actual KFD-assigned value */
	amd_queue = (struct amd_queue *)knod->kaql[idx].queue->kaddr;
	amd_queue->hsa_queue.id = knod->aql_queue_id[idx];
	return 0;

err_mem:
	if (knod->aql_event[idx].id) {
		knod_destroy_event(knod->process, knod->aql_event[idx].id);
		knod->aql_event[idx].id = 0;
	}
	knod_free_mem(knod, knod->kaql[idx].aql);
	knod_free_mem(knod, knod->kaql[idx].queue);
	knod_free_mem(knod, knod->kaql[idx].eop);
	knod_free_mem(knod, knod->kaql[idx].ctx);
	knod_free_mem(knod, knod->kaql[idx].queue_signal);
	knod_free_mem(knod, knod->kaql[idx].amd_queue);
	knod_free_mem(knod, knod->kaql[idx].scratch);
	memset(&knod->kaql[idx], 0, sizeof(knod->kaql[idx]));
	return err;
}

/*
 * Write a minimal no-op kernel into the kernel BO so that any dispatch
 * before a real shader (BPF/IPsec/MACsec/WG) is loaded executes a
 * harmless s_endpgm instead of faulting on uninitialised VRAM.
 *
 * Layout:
 *   [0..63]     kernel_descriptor  (kernel_code_entry_byte_offset = 256)
 *   [256..259]  s_endpgm           (0xBF810000)
 *   [260..1023] s_code_end padding (GFX10 SQC prefetch safety)
 */
#define KNOD_DEFAULT_KD_ENTRY_OFFSET	256
#define KNOD_S_ENDPGM			0xBF810000u
#define KNOD_S_CODE_END			0xBF9F0000u

static void knod_init_default_kernel(struct knod *knod)
{
	struct kernel_descriptor *kd = knod->kernels[0]->kaddr;
	u32 *code = (u32 *)((u8 *)knod->kernels[0]->kaddr +
			    KNOD_DEFAULT_KD_ENTRY_OFFSET);
	int i;

	memset(kd, 0, sizeof(*kd));
	kd->kernel_code_entry_byte_offset = KNOD_DEFAULT_KD_ENTRY_OFFSET;
	kd->compute_pgm_rsrc1.granulated_workitem_vgpr_count = 0;
	kd->compute_pgm_rsrc1.granulated_wavefront_sgpr_count = 0;
	kd->compute_pgm_rsrc1.float_denorm_mode_32 = 3;
	kd->compute_pgm_rsrc1.float_denorm_mode_16_64 = 3;
	kd->compute_pgm_rsrc1.enable_dx10_clamp = 1;
	kd->compute_pgm_rsrc1.enable_ieee_mode = 1;
	if (knod->isa_version >= 10)
		kd->compute_pgm_rsrc1.mem_ordered = 1;
	kd->compute_pgm_rsrc2.enable_sgpr_workgroup_id_x = 1;

	code[0] = KNOD_S_ENDPGM;
	for (i = 1; i < (1024 - KNOD_DEFAULT_KD_ENTRY_OFFSET) / 4; i++)
		code[i] = KNOD_S_CODE_END;
}

#define KNOD_DEFAULT_BATCH	64

static struct knod_accel_xdp_ops *registered_xdp_ops;

/*
 * feature=none has no per-feature ops: the default worker stamps XDP_PASS and
 * the NIC act handler delivers via knod_d2h_copy / knod_d2h_drain.
 */
static struct knod_accel_xdp_ops default_xdp_ops = {
};

static int knod_default_worker(void *arg)
{
	struct knod *knod = arg;
	struct spsc_bd *bds[KNOD_DEFAULT_BATCH];
	struct knod_dev *knodev;
	unsigned int cnt;
	int qi, i;

	while (!kthread_should_stop()) {
		knodev = READ_ONCE(knod->accel->knodev);
		if (!knodev || !knodev->started) {
			usleep_range(1000, 2000);
			continue;
		}

		for (qi = 0; qi < knod->channels; qi++) {
			struct knod_work_priv *wpriv = &knodev->wpriv[qi];

			if (!wpriv->napi)
				continue;

			if (spsc_peek(&wpriv->spsc_bds, (void **)bds,
				      KNOD_DEFAULT_BATCH, &cnt))
				continue;

			/*
			 * feature=none has no program, so every packet passes.
			 * Stamp the verdict before advancing the consumer
			 * cursor: spsc_acquire() publishes the window with a
			 * release barrier the act handler pairs with, so the
			 * verdict has to be written first or the act handler
			 * races a POISON read.  The NIC act handler does the
			 * device->host delivery via knod_d2h_copy.
			 */
			for (i = 0; i < cnt; i++)
				WRITE_ONCE(bds[i]->act, XDP_PASS);

			spsc_acquire(&wpriv->spsc_bds, NULL, cnt, NULL);
			knod_napi_kick(wpriv);
		}

		usleep_range(100, 200);
	}
	return 0;
}

static int knod_start_default_worker(struct knod *knod)
{
	struct task_struct *p;

	knod->worker_fn = knod_default_worker;
	knod->flush_fn = NULL;
	knod->worker_ctx = knod;
	p = kthread_run(knod_default_worker, knod, "knod_dflt_%d",
			knod->accel->id);
	if (IS_ERR(p))
		return PTR_ERR(p);

	get_task_struct(p);
	knod->worker = p;
	return 0;
}

static void knod_stop_worker(struct knod *knod)
{
	if (!knod->worker)
		return;

	if (knod->flush_fn)
		knod->flush_fn(knod->worker_ctx);

	kthread_stop(knod->worker);
	put_task_struct(knod->worker);
	knod->worker = NULL;
	knod->worker_fn = NULL;
	knod->flush_fn = NULL;
	knod->worker_ctx = NULL;
}

int knod_register_worker(struct knod *knod, knod_worker_fn_t fn,
			 knod_flush_fn_t flush, void *ctx)
{
	struct task_struct *p;

	knod_stop_worker(knod);

	knod->worker_fn = fn;
	knod->flush_fn = flush;
	knod->worker_ctx = ctx;
	p = kthread_run(fn, ctx, "knod_%d", knod->accel->id);
	if (IS_ERR(p)) {
		knod->worker_fn = NULL;
		knod->flush_fn = NULL;
		knod->worker_ctx = NULL;
		return PTR_ERR(p);
	}

	get_task_struct(p);
	knod->worker = p;
	return 0;
}

void knod_unregister_worker(struct knod *knod)
{
	knod_stop_worker(knod);
	knod_start_default_worker(knod);
}

int knod_wait_on_events(struct kfd_process *p, u32 num_events,
			void __user *data, bool all, u32 *user_timeout_ms,
			u32 *wait_result)
{
	return kfd_wait_on_events_kernel(p, num_events, data, all,
					 user_timeout_ms, wait_result);
}
EXPORT_SYMBOL(knod_wait_on_events);

static int knod_alloc_ctx_init(struct knod *knod, int id, void **doorbell,
			       struct kfd_topology_device **out_topo_dev,
			       struct kfd_process_device **out_pdd)
{
	struct kfd_topology_device *topo_dev;
	struct kfd_process_device *pdd;
	struct file *drm_file;
	size_t mem_size;
	char path[64];
	int err;

	sprintf(path, "/dev/dri/renderD%d", id);

	drm_file = filp_open(path, O_RDWR, 0);
	if (IS_ERR(drm_file))
		return PTR_ERR(drm_file);

	knod->drm_file = drm_file;

	knod->process = kfd_create_process(knod->umh_task);
	if (IS_ERR(knod->process)) {
		err = PTR_ERR(knod->process);
		goto err_filp_close;
	}
	kref_get(&knod->process->ref);

	err = knod_set_isa(knod);
	if (err < 0)
		goto err_unref_process;

	pdd = knod->process->pdds[0];

	topo_dev = kfd_topology_device_by_id(pdd->dev->id);
	if (!topo_dev) {
		pr_err("knod: can't find topo_dev for dev id %u\n",
		       pdd->dev->id);
		err = -ENODEV;
		goto err_unref_process;
	}

	/* Acquire VM directly without installing an fd into any process's
	 * fdtable.  get_file() provides the ref that pdd->drm_file will own.
	 * kfd_process_destroy_pdds will fput it during process cleanup.
	 */
	get_file(drm_file);
	mutex_lock(&knod->process->mutex);
	err = kfd_process_device_init_vm(pdd, drm_file);
	mutex_unlock(&knod->process->mutex);
	if (err) {
		fput(drm_file);
		goto err_unref_process;
	}

	*doorbell = kfd_kernel_doorbell_mmap(pdd->dev, knod->process);
	if (!*doorbell) {
		err = -ENOMEM;
		goto err_unref_process;
	}

	knod->pool = gen_pool_create(PAGE_SHIFT,
				     dev_to_node(pdd->dev->adev->dev));
	if (!knod->pool) {
		err = -ENOMEM;
		goto err_release_doorbell;
	}

	knod->dev = pdd->dev;
	knod->reserved_addr = pdd->gpuvm_base << 2;
	knod->limit_addr = pdd->gpuvm_limit;
	mem_size = knod->limit_addr - knod->reserved_addr;

	err = gen_pool_add(knod->pool, knod->reserved_addr, mem_size,
			   dev_to_node(pdd->dev->adev->dev));
	if (err)
		goto err_gen_pool_destroy;

	knod->kernels[0] = knod_alloc_mem(knod, PAGE_SIZE << 10,
				      KFD_IOC_ALLOC_MEM_FLAGS_VRAM |
				      KFD_IOC_ALLOC_MEM_FLAGS_COHERENT |
				      KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
				      KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE);
	if (IS_ERR(knod->kernels[0])) {
		err = PTR_ERR(knod->kernels[0]);
		knod->kernels[0] = NULL;
		goto err_gen_pool_destroy;
	}
	knod_init_default_kernel(knod);

	/*
	 * Second dispatch slot for the BPF ping-pong swap, allocated right
	 * after knod->kernels[0] so both kernel BOs sit in the same low VA
	 * region.
	 * Allocating it later (at feature activate, past the RX buffers) put it
	 * at a high VA, and switching the dispatch kernel_object to that BO
	 * mid-stream wedged the compute queue.
	 */
	knod->kernels[1] = knod_alloc_mem(knod, PAGE_SIZE << 10,
					  KFD_IOC_ALLOC_MEM_FLAGS_VRAM |
					  KFD_IOC_ALLOC_MEM_FLAGS_COHERENT |
					  KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
					  KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE);
	if (IS_ERR(knod->kernels[1])) {
		err = PTR_ERR(knod->kernels[1]);
		knod->kernels[1] = NULL;
		goto err_free_kernel;
	}

	knod->mailbox = knod_alloc_mem(knod, PAGE_SIZE << 5,
				       KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE |
				       KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
				       KFD_IOC_ALLOC_MEM_FLAGS_COHERENT |
				       KFD_IOC_ALLOC_MEM_FLAGS_VRAM);
	if (IS_ERR(knod->mailbox)) {
		err = PTR_ERR(knod->mailbox);
		knod->mailbox = NULL;
		goto err_free_kernel;
	}

	*out_topo_dev = topo_dev;
	*out_pdd = pdd;
	return 0;

err_free_kernel:
	if (knod->kernels[1])
		knod_free_mem(knod, knod->kernels[1]);
	knod->kernels[1] = NULL;
	knod_free_mem(knod, knod->kernels[0]);
	knod->kernels[0] = NULL;
err_gen_pool_destroy:
	gen_pool_destroy(knod->pool);
	knod->pool = NULL;
err_release_doorbell:
	iounmap(*doorbell);
	*doorbell = NULL;
err_unref_process:
	kfd_unref_process(knod->process);
err_filp_close:
	fput(knod->drm_file);
	return err;
}

struct knod *knod_alloc_ctx(struct knod_dev *knodev, int queue_cnt, int id,
			    int channels)
{
	int buf_flags = KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
			KFD_IOC_ALLOC_MEM_FLAGS_COHERENT |
			KFD_IOC_ALLOC_MEM_FLAGS_VRAM;
	struct kfd_topology_device *topo_dev;
	struct kfd_process_device *pdd;
	struct process_queue_node *pqn;
	struct knod_work_priv *wpriv;
	struct task_struct *task;
	unsigned int sdma_cnt;
	void *ptr = NULL;
	struct knod *knod;
	struct knod_mem *buf;
	struct pid *spid;
	struct queue *q;
	int err, size;
	pid_t pid;
	int idx;

	pid = launch_and_get_pid();
	if (!pid) {
		knod_err(" failed to create UMH\n");
		return ERR_PTR(-EINVAL);
	}

	spid = find_get_pid(pid);
	if (!spid) {
		knod_err(" failed to find pid\n");
		return ERR_PTR(-ESRCH);
	}

	task = get_pid_task(spid, PIDTYPE_PID);
	put_pid(spid);
	if (!task) {
		knod_err(" no task found\n");
		return ERR_PTR(-ESRCH);
	}

	knod = kzalloc(sizeof(struct knod), GFP_KERNEL);
	if (!knod) {
		put_task_struct(task);
		return ERR_PTR(-ENOMEM);
	}

	knod->queue_cnt = queue_cnt;
	knod->sdma_cnt = queue_cnt;
	knod->channels = channels;
	knod->umh_pid = pid;
	knod->umh_task = task;
	knod->nr_aql_ring = NR_AQL_RING;
	INIT_LIST_HEAD(&knod->list);
	INIT_LIST_HEAD(&knod->active_list);

	err = knod_alloc_ctx_init(knod, id, &ptr, &topo_dev, &pdd);
	if (err)
		goto err_free_knod;

	sdma_cnt = topo_dev->node_props.num_sdma_engines *
		   topo_dev->node_props.num_sdma_queues_per_engine;
	if (!sdma_cnt)
		sdma_cnt = queue_cnt;
	knod->sdma_cnt = min_t(int, queue_cnt, sdma_cnt);
	if (!knod->sdma_cnt)
		knod->sdma_cnt = 1;
	pr_info("knod: AQL queues=%d SDMA queues=%d channels=%d\n",
		queue_cnt, knod->sdma_cnt, channels);

	knod->doorbell_base = ptr;

	knod->buf = kmalloc_array(channels, sizeof(struct knod_mem *),
				  GFP_KERNEL | __GFP_ZERO);
	if (!knod->buf) {
		err = -ENOMEM;
		goto err_free_mailbox;
	}

	if (knod->igpu)
		size = PAGE_SIZE << MAX_PAGE_ORDER;
	else
		size = PAGE_SIZE << 14;

	for (idx = 0; idx < channels; idx++) {
		wpriv = &knodev->wpriv[idx];
		buf = __knod_alloc_mem(knod, size, buf_flags);
		if (IS_ERR(buf)) {
			err = PTR_ERR(buf);
			goto err_free_bufs;
		}
		if (__knod_export_dma_buf(knod, buf)) {
			knod_free_mem(knod, buf);
			err = -ENOMEM;
			goto err_free_bufs;
		}
		if (__knod_map_kaddr(knod, buf)) {
			knod_free_mem(knod, buf);
			err = -ENOMEM;
			goto err_free_bufs;
		}
		if (__knod_map_mem(knod, buf)) {
			knod_free_mem(knod, buf);
			err = -ENOMEM;
			goto err_free_bufs;
		}
		wpriv->dmabuf = buf->mem->dmabuf;
		wpriv->index = idx;
		knod->buf[idx] = buf;
	}

	/*
	 * GPU->host delivery buffer + per-queue page_pools are owned by the
	 * NOD framework (knod_pass_attach), allocated via accel_ops->alloc_mem.
	 */

	memset(knod->mailbox->kaddr, 0, knod->mailbox->size);

	err = kfd_event_page_set(knod->process,
				 knod->mailbox->kaddr,
				 KFD_SIGNAL_EVENT_LIMIT * 8,
				 knod->mailbox->gaddr);
	if (err < 0)
		goto err_free_bufs;

	for (idx = 0; idx < queue_cnt; idx++) {
		err = knod_alloc_one_queue(knod, idx, topo_dev, pdd, ptr);
		if (err)
			goto err_free_queues;
	}

	/* Allocate only the SDMA queues the device can actually provide. BPF
	 * XDP_TX does not use SDMA for the verdict path, while PASS/d2h maps RX
	 * queues onto the available SDMA queues modulo sdma_cnt.
	 */
	for (idx = 0; idx < knod->sdma_cnt; idx++) {
		struct amd_signal *sdma_signal;
		struct queue_properties qp;
		long *sdma_lptr;
		int sdma_flags = KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE |
				 KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
				 KFD_IOC_ALLOC_MEM_FLAGS_COHERENT |
				 KFD_IOC_ALLOC_MEM_FLAGS_GTT;

		knod->sdma[idx].sdma = knod_alloc_mem(knod, PAGE_SIZE << 4,
			KFD_IOC_ALLOC_MEM_FLAGS_GTT |
			KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
			KFD_IOC_ALLOC_MEM_FLAGS_COHERENT |
			KFD_IOC_ALLOC_MEM_FLAGS_UNCACHED |
			KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE);
		if (IS_ERR(knod->sdma[idx].sdma)) {
			err = PTR_ERR(knod->sdma[idx].sdma);
			knod->sdma[idx].sdma = NULL;
			goto err_free_sdma;
		}
		knod->sdma[idx].queue = knod_alloc_mem(knod, PAGE_SIZE,
						       sdma_flags);
		if (IS_ERR(knod->sdma[idx].queue)) {
			err = PTR_ERR(knod->sdma[idx].queue);
			knod->sdma[idx].queue = NULL;
			goto err_free_sdma;
		}
		knod->sdma[idx].queue_signal = knod_alloc_mem(knod,
			PAGE_SIZE << 5,
			KFD_IOC_ALLOC_MEM_FLAGS_GTT |
			KFD_IOC_ALLOC_MEM_FLAGS_COHERENT |
			KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE |
			KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE);
		if (IS_ERR(knod->sdma[idx].queue_signal)) {
			err = PTR_ERR(knod->sdma[idx].queue_signal);
			knod->sdma[idx].queue_signal = NULL;
			goto err_free_sdma;
		}
		knod->sdma[idx].idx = 0;

		err = knod_create_event(knod->process, KFD_IOC_EVENT_SIGNAL,
					true, 1, &knod->sdma_event[idx]);
		if (err) {
			knod_err(" failed to create SDMA event[%d] err=%d\n",
				 idx, err);
			goto err_free_sdma;
		}

		memset(&qp, 0, sizeof(qp));
		qp.type = KFD_QUEUE_TYPE_SDMA;
		qp.format = KFD_QUEUE_FORMAT_PM4;
		qp.queue_percent = 100;
		qp.priority = 15;
		qp.queue_address = (u64)knod->sdma[idx].sdma->gaddr;
		qp.queue_size = knod->sdma[idx].sdma->size;
		qp.write_ptr = (void __user *)
			((u64)knod->sdma[idx].queue->gaddr + 0x08);
		qp.read_ptr = (void __user *)
			((u64)knod->sdma[idx].queue->gaddr + 0x10);

		sdma_signal = (struct amd_signal *)
			knod->sdma[idx].queue_signal->kaddr;
		sdma_signal->kind = AMD_SIGNAL_KIND_USER;
		sdma_signal->event_id = knod->sdma_event[idx].id;
		sdma_signal->queue_ptr = 0;
		sdma_signal->event_mailbox_ptr = knod->mailbox->gaddr +
			(knod->sdma_event[idx].slot * 8);
		/* SDMA fence writes u32 to low 32 bits of value.
		 * Init to 0 (not -1 like AQL) so comparison works.
		 * value is in union with hardware_doorbell_ptr - set last.
		 */
		sdma_signal->value = 0;
		sdma_lptr = knod->mailbox->kaddr + (idx * 8);
		sdma_lptr[knod->sdma_event[idx].slot] = 0;

		err = knod_create_queue(knod->process, &qp, pdd->user_gpu_id,
					&knod->sdma_queue_id[idx],
					&knod->sdma_doorbell_offset[idx]);
		if (err) {
			knod_err(" failed to create SDMA queue[%d] err=%d\n",
				 idx, err);
			goto err_free_sdma;
		}
		knod->sdma_queue_created[idx] = true;

		knod_init_queue(knod, knod->sdma_queue_id[idx], idx,
				KFD_IOC_QUEUE_TYPE_SDMA);
		knod->sdma[idx].doorbell =
			(u64 *)((u8 *)ptr +
				(u32)knod->sdma_doorbell_offset[idx]);
		knod_dbg(" SDMA queue[%d] created: id=%d doorbell_offset=0x%x doorbell=%p\n",
			 idx, knod->sdma_queue_id[idx],
			 (u32)knod->sdma_doorbell_offset[idx],
			 knod->sdma[idx].doorbell);
	}

	list_for_each_entry(pqn, &knod->process->pqm.queues,
			    process_queue_list) {
		if (!pqn->q)
			continue;
		q = pqn->q;
		for (idx = 0; idx < queue_cnt; idx++) {
			if (q->properties.queue_id == idx) {
				knod->kaql[idx].doorbell =
					(u64 *)((u8 *)ptr +
					(u32)knod->aql_doorbell_offset[idx]);
				q->properties.doorbell_ptr =
					knod->kaql[idx].doorbell;
				knod_dbg(" doorbell: idx=%d qid=%d door_off=0x%x doorbell=%p\n",
					 idx, q->properties.queue_id,
					 (u32)knod->aql_doorbell_offset[idx],
					 knod->kaql[idx].doorbell);
			}
		}
	}

	list_add_tail(&knod->list, &ctx_list);

	/* Create shared debugfs directory under dri/<N>/knod/ */
	{
		struct drm_minor *minor = adev_to_drm(pdd->dev->adev)->render;

		if (minor && minor->debugfs_root) {
			struct dentry *dir;

			dir = debugfs_lookup("knod", minor->debugfs_root);
			if (!dir) {
				dir = debugfs_create_dir("knod",
							 minor->debugfs_root);
				if (IS_ERR(dir))
					dir = NULL;
			}
			knod->debug_dir = dir;
		}
	}

	return knod;

err_free_sdma:
	{
		int j;

		for (j = idx; j >= 0; j--) {
			if (knod->sdma_queue_created[j]) {
				knod_destroy_queue(knod->process,
						   knod->sdma_queue_id[j]);
				knod->sdma_queue_created[j] = false;
			}
			if (knod->sdma_event[j].id) {
				knod_destroy_event(knod->process,
						   knod->sdma_event[j].id);
				knod->sdma_event[j].id = 0;
			}
			knod_free_mem(knod, knod->sdma[j].sdma);
			knod_free_mem(knod, knod->sdma[j].queue);
			knod_free_mem(knod, knod->sdma[j].queue_signal);
		}
	}
	idx = queue_cnt;
err_free_queues:
	while (idx-- > 0)
		knod_destroy_one_queue(knod, idx);
err_free_bufs:
	for (idx = 0; idx < channels; idx++)
		knod_free_mem(knod, knod->buf[idx]);
	kfree(knod->buf);
err_free_mailbox:
	knod_free_mem(knod, knod->mailbox);
	knod_free_mem(knod, knod->kernels[1]);
	knod_free_mem(knod, knod->kernels[0]);
	gen_pool_destroy(knod->pool);
	iounmap(ptr);
	kfd_unref_process(knod->process);
	fput(knod->drm_file);
err_free_knod:
	put_task_struct(knod->umh_task);
	stop_umh(knod->umh_pid);
	kfree(knod);
	return ERR_PTR(err);
}
EXPORT_SYMBOL(knod_alloc_ctx);

void knod_release_ctx(struct knod *knod)
{
	int idx;

	list_del(&knod->list);

	debugfs_remove_recursive(knod->debug_dir);

	/* Release SDMA queues - destroy queue/event BEFORE freeing BOs.
	 * Same ordering as knod_destroy_one_queue() for AQL: the queue
	 * holds references to BO VAs, so freeing BOs first causes the
	 * queue destroy to fail and leaves internal BOs in kfd_bo_list.
	 */
	for (idx = 0; idx < knod->sdma_cnt; idx++) {
		knod_destroy_queue(knod->process, knod->sdma_queue_id[idx]);
		knod_destroy_event(knod->process, knod->sdma_event[idx].id);
		knod_free_mem(knod, knod->sdma[idx].sdma);
		knod_free_mem(knod, knod->sdma[idx].queue);
		knod_free_mem(knod, knod->sdma[idx].queue_signal);
	}

	for (idx = 0; idx < knod->queue_cnt; idx++)
		knod_destroy_one_queue(knod, idx);

	for (idx = 0; idx < knod->channels; idx++)
		knod_free_mem(knod, knod->buf[idx]);
	kfree(knod->buf);

	knod_free_mem(knod, knod->mailbox);
	knod_free_mem(knod, knod->kernels[1]);
	knod_free_mem(knod, knod->kernels[0]);
	gen_pool_destroy(knod->pool);
	iounmap(knod->doorbell_base);

	/* Tear down the KFD process.  It holds 3 refs:
	 *   ref 1: "open" ref from kfd_create_process (normally dropped
	 *           by kfd_release when /dev/kfd is closed - KNOD never
	 *           opens /dev/kfd so we must drop this ourselves)
	 *   ref 2: KNOD's explicit kref_get in knod_alloc_ctx
	 *   ref 3: mmu_notifier alloc_notifier ref (dropped by
	 *           free_notifier callback via SRCU after mmu_notifier_put)
	 *
	 * kfd_process_notifier_release_internal removes from hash,
	 * destroys queues, and calls mmu_notifier_put which schedules
	 * the SRCU callback to drop ref 3.  We drop refs 1 and 2 here.
	 * After SRCU fires, ref reaches 0 -> kfd_process_wq_release
	 * runs (sysfs removal, BO/PDD/doorbell/event cleanup, kfree).
	 *
	 * kfd_process_destroy_pdds fput's pdd->drm_file (the get_file
	 * ref from init_vm), bringing the DRM file ref from 2->1.
	 * The file/VM stays alive until we fput the filp_open ref below.
	 */
	kfd_process_notifier_release_internal(knod->process);
	kfd_unref_process(knod->process);
	kfd_unref_process(knod->process);
	mmu_notifier_synchronize();
	kfd_process_flush_wq();

	/* Drop the filp_open ref (file ref 1->0).  kfd_process_destroy_pdds
	 * already fput'd the get_file ref during wq_release above.
	 */
	fput(knod->drm_file);
	flush_delayed_fput();

	stop_umh(knod->umh_pid);
	put_task_struct(knod->umh_task);
	kfree(knod);
}
EXPORT_SYMBOL(knod_release_ctx);

/* ---- feature control (knod genetlink) ---- */

static void *knod_feature_ops(enum knod_feature feat)
{
	switch (feat) {
	case KNOD_FEATURE_BPF:
		return registered_xdp_ops;
	case KNOD_FEATURE_IPSEC:
		return accel_ops.ipsec_ops;
	default:
		return NULL;
	}
}

/*
 * Feature lifecycle across three independent axes:
 *   init/exit            attach/detach      permanent per-attach state
 *   activate/deactivate  feature select     feature GPU resources
 *   start/stop           interface up/down  worker + GPU in-flight drain
 *
 * The worker only does useful work while (interface up AND a feature is
 * selected), so a feature switch is bracketed stop -> change -> start: the
 * worker is stopped and its GPU dispatch drained before deactivate() frees
 * the resources it used, then restarted afterwards.  start/stop never touch
 * the framework/NIC-owned RX SPSC ring (mlx5 co-owns it via rq->knodev), so
 * they are safe to run while the interface is up and traffic is flowing.
 */
static void knod_feature_stop(struct knod *knod)
{
	struct knod_dev *knodev = knod->accel->knodev;

	knod_stop_worker(knod);

	switch (knod->active_feature) {
	case KNOD_FEATURE_BPF:
		if (registered_xdp_ops && registered_xdp_ops->stop)
			registered_xdp_ops->stop(knodev);
		break;
	case KNOD_FEATURE_IPSEC:
		if (accel_ops.ipsec_ops && accel_ops.ipsec_ops->stop)
			accel_ops.ipsec_ops->stop(knodev);
		break;
	default:
		break;
	}
}

static void knod_feature_start(struct knod *knod)
{
	struct knod_dev *knodev = knod->accel->knodev;

	switch (knod->active_feature) {
	case KNOD_FEATURE_BPF:
		if (registered_xdp_ops && registered_xdp_ops->start)
			registered_xdp_ops->start(knodev);
		break;
	case KNOD_FEATURE_IPSEC:
		if (accel_ops.ipsec_ops && accel_ops.ipsec_ops->start)
			accel_ops.ipsec_ops->start(knodev);
		break;
	default:
		knod_start_default_worker(knod);
		break;
	}
}

static void knod_feature_deactivate(struct knod *knod)
{
	struct knod_dev *knodev = knod->accel->knodev;

	switch (knod->active_feature) {
	case KNOD_FEATURE_BPF:
		/*
		 * Phase 1: unregister the offload dev - this force-frees any
		 * user XDP progs/maps still bound.  The map-free ndo routes
		 * back through accel_ops.xdp_ops->xdp_install, so xdp_ops must
		 * still point at the BPF ops (and priv must be alive) here.
		 */
		if (registered_xdp_ops &&
		    registered_xdp_ops->xdp_offload_uninit)
			registered_xdp_ops->xdp_offload_uninit(knodev);
		/*
		 * Phase 2: repoint RX delivery at the default drain_pass and
		 * wait out the in-flight NAPI readers.
		 */
		WRITE_ONCE(accel_ops.xdp_ops, &default_xdp_ops);
		synchronize_net();
		knod_stop_worker(knod);
		if (registered_xdp_ops && registered_xdp_ops->deactivate)
			registered_xdp_ops->deactivate(knodev);
		break;
	case KNOD_FEATURE_IPSEC:
		/*
		 * knod_ipsec_detach() clears the netdev xfrm flags and runs
		 * ->deactivate(), which NULLs ipsec_priv and does its own
		 * synchronize_net() before freeing.
		 */
		knod_ipsec_detach(knodev);
		break;
	default:
		break;
	}
}

static int knod_feature_activate(struct knod *knod)
{
	struct knod_dev *knodev = knod->accel->knodev;
	int err;

	switch (knod->active_feature) {
	case KNOD_FEATURE_BPF:
		if (!registered_xdp_ops)
			return -ENODEV;
		/* Phase A: GPU compute buffers. */
		if (registered_xdp_ops->activate) {
			err = registered_xdp_ops->activate(knodev);
			if (err)
				return err;
		}
		/*
		 * Publish xdp_ops, then phase B: register the offload dev so
		 * user XDP progs/maps can bind (their install/free route
		 * through accel_ops.xdp_ops->xdp_install).
		 */
		WRITE_ONCE(accel_ops.xdp_ops, registered_xdp_ops);
		if (registered_xdp_ops->xdp_offload_init) {
			err = registered_xdp_ops->xdp_offload_init(knodev);
			if (err) {
				WRITE_ONCE(accel_ops.xdp_ops, &default_xdp_ops);
				synchronize_net();
				knod_stop_worker(knod);
				if (registered_xdp_ops->deactivate)
					registered_xdp_ops->deactivate(knodev);
				return err;
			}
		}
		return 0;
	case KNOD_FEATURE_IPSEC:
		if (!accel_ops.ipsec_ops)
			return -ENODEV;
		/* knod_ipsec_attach() runs ->activate() + sets netdev flags. */
		return knod_ipsec_attach(knodev);
	case KNOD_FEATURE_NONE:
		return 0;
	default:
		return -EINVAL;
	}
}

static int knod_accel_feature_get(struct knod_accel *accel,
				u32 *ena, u32 *cap)
{
	struct knod *knod = READ_ONCE(accel->priv);
	u32 mask = 0;
	int i;

	/* A registered-but-not-attached accel has no context yet. */
	*ena = knod ? knod->active_feature : KNOD_FEATURE_NONE;
	for (i = 0; i < KNOD_FEATURE_MAX; i++)
		if (i == KNOD_FEATURE_NONE || knod_feature_ops(i))
			mask |= BIT(i);
	*cap = mask;
	return 0;
}

static int knod_accel_feature_set(struct knod_accel *accel, u32 feature,
				struct netlink_ext_ack *extack)
{
	struct knod *knod = READ_ONCE(accel->priv);
	struct knod_dev *knodev;
	bool started;
	int err = 0;

	if (feature >= KNOD_FEATURE_MAX) {
		NL_SET_ERR_MSG(extack, "unknown feature");
		return -EINVAL;
	}
	if (feature != KNOD_FEATURE_NONE && !knod_feature_ops(feature)) {
		NL_SET_ERR_MSG(extack, "feature not available on this accelerator");
		return -ENOENT;
	}
	knodev = knod ? READ_ONCE(knod->accel->knodev) : NULL;
	if (!knod || !knodev) {
		NL_SET_ERR_MSG(extack, "accelerator not attached to a NIC");
		return -ENODEV;
	}
	if (feature == knod->active_feature)
		return 0;

	/*
	 * Refuse to leave BPF while a user XDP prog or offloaded map is still
	 * bound - tearing the offload down underneath them is unsafe (the GPU
	 * dispatch keeps running against freed state).  The user must detach
	 * first, e.g. "ip link set dev <if> xdp off".
	 */
	if (knod->active_feature == KNOD_FEATURE_BPF && registered_xdp_ops &&
	    registered_xdp_ops->busy && registered_xdp_ops->busy(knodev)) {
		NL_SET_ERR_MSG(extack, "detach the XDP program/maps first");
		return -EBUSY;
	}
	if (knod->active_feature == KNOD_FEATURE_IPSEC && accel_ops.ipsec_ops &&
	    accel_ops.ipsec_ops->busy && accel_ops.ipsec_ops->busy(knodev)) {
		NL_SET_ERR_MSG(extack, "remove the offloaded xfrm SAs first");
		return -EBUSY;
	}

	/*
	 * stop -> change -> start.  The worker only runs while the interface
	 * is up; bracket the resource change with worker stop/start in that
	 * case.  stop() drains the GPU in-flight so deactivate() frees safely.
	 */
	started = READ_ONCE(knodev->started);
	if (started)
		knod_feature_stop(knod);
	knod_feature_deactivate(knod);
	knod->active_feature = KNOD_FEATURE_NONE;

	if (feature != KNOD_FEATURE_NONE) {
		knod->active_feature = feature;
		err = knod_feature_activate(knod);
		if (err) {
			knod->active_feature = KNOD_FEATURE_NONE;
			NL_SET_ERR_MSG(extack, "failed to activate feature");
		}
	}
	if (started)
		knod_feature_start(knod);
	return err;
}

static int knod_attach(struct knod_dev *knodev)
{
	struct knod_accel *accel = knodev->accel;
	int render_idx = accel->id / KNOD_MAX_AQL;
	struct net_device *netdev = knodev->netdev;
	struct amdgpu_device *adev;
	struct knod *knod;

	{
		int q_cnt = clamp(READ_ONCE(knod_requested_queue_cnt), 1,
				      KNOD_MAX_QUEUE_CNT);

		knod = knod_alloc_ctx(knodev, q_cnt, render_idx,
				      min(netdev->num_rx_queues,
					  KNOD_SPSC_MAX));
	}
	if (IS_ERR(knod)) {
		pr_err("knod: Failed to allocate context\n");
		return -EINVAL;
	}

	accel->priv = knod;
	knod->accel = accel;

	/*
	 * Keep GFX engine out of GFXOFF while a KNOD accel is attached.
	 * On RDNA2 (tested RX6600 / gfx1032) the very first AQL dispatch
	 * after boot hangs with signal=-1 when GFXOFF is active - SMU exit
	 * from GFXOFF races with the doorbell ring and the completion
	 * signal is never decremented. Forcing GFXOFF off for the attached
	 * lifetime avoids the race entirely.
	 *
	 * Pin MCLK soft-min to HW max. KNOD's RX path is bandwidth-bound
	 * on VRAM (NIC->GPU p2pdma delivers frames directly to VRAM, then
	 * the shader streams them back out) but the individual dispatches
	 * are too short for SMU's activity monitor to react - MCLK sticks
	 * at the lowest DPM (~96 MHz on RX6600) in AUTO mode and caps
	 * throughput far below what the compute path can sustain. Switching
	 * to the COMPUTE power profile did not help on RDNA2: the COMPUTE
	 * DpmActivityMonitor coefficients tune GFX upclock aggressively
	 * but leave memory activity detection conservative.
	 *
	 * Setting soft_min via SetSoftMinByFreq is independent of
	 * pp_power_profile_mode and of power_dpm_force_performance_level,
	 * so AUTO governance stays in effect for SCLK/voltage - we get the
	 * same 30W full-throughput state the user reaches via "force
	 * performance = manual + echo 3 > pp_dpm_mclk", without the 75W
	 * voltage pin that PROFILE_PEAK imposes. Passing 0xFFFF MHz lets
	 * SMU firmware clamp to the actual hardware max.
	 */
	adev = knod->process->pdds[0]->dev->adev;
	amdgpu_gfx_off_ctrl_immediate(adev, false);
	amdgpu_dpm_set_soft_freq_range(adev, PP_MCLK, 0xFFFF, 0xFFFF);

	/*
	 * Attach settles in KNOD_FEATURE_NONE with no worker running.  The
	 * worker is started by the NIC driver bringing the interface up
	 * (knod_dev_start -> ->dev_start), and each feature's GPU resources
	 * are allocated when the feature is selected (->activate).
	 */
	knod->active_feature = KNOD_FEATURE_NONE;

	/*
	 * Permanent per-attach feature state (e.g. the BPF bpf_offload_dev,
	 * which must outlive feature switches so user XDP progs/maps survive).
	 */
	if (registered_xdp_ops && registered_xdp_ops->init)
		registered_xdp_ops->init(knodev);
	return 0;
}

static void knod_pre_detach(struct knod_dev *knodev)
{
	struct knod *knod = knodev->accel->priv;

	/*
	 * Detach requires the interface down, so the worker is already
	 * stopped; stop again defensively, free the active feature's
	 * resources, then tear down the permanent per-attach state.
	 */
	knod_feature_stop(knod);
	knod_feature_deactivate(knod);
	knod->active_feature = KNOD_FEATURE_NONE;

	if (registered_xdp_ops && registered_xdp_ops->exit)
		registered_xdp_ops->exit(knodev);
}

static void knod_dev_start_worker(struct knod_dev *knodev)
{
	struct knod *knod = knodev->accel->priv;

	/* Interface up: start the current feature's worker. */
	if (knod)
		knod_feature_start(knod);
}

static void knod_dev_stop_worker(struct knod_dev *knodev)
{
	struct knod *knod = knodev->accel->priv;

	/* Interface down: stop the worker + drain the GPU in-flight. */
	if (knod)
		knod_feature_stop(knod);
}

static void knod_detach(struct knod_dev *knodev)
{
	struct knod_accel *accel = knodev->accel;
	struct knod *knod = accel->priv;
	struct amdgpu_device *adev = knod->process->pdds[0]->dev->adev;

	knod_stop_worker(knod);
	knod_release_ctx(knod);
	WRITE_ONCE(accel->priv, NULL);

	/*
	 * Restore default MCLK range. min=1 triggers SetSoftMinByFreq (the
	 * API skips the call when min==0) and SMU clamps to HW min; max
	 * 0xFFFF clamps to HW max. Together this matches the pre-attach
	 * "no soft constraint" state so DPM can idle MCLK back down.
	 */
	amdgpu_dpm_set_soft_freq_range(adev, PP_MCLK, 1, 0xFFFF);
	amdgpu_gfx_off_ctrl(adev, true);
}

static void *knod_accel_alloc_mem(struct knod_dev *knodev, size_t size,
				  u64 *gaddr, struct page ***pages, void **priv)
{
	struct knod_accel *accel = knodev->accel;
	struct knod *knod = accel->priv;
	struct knod_mem *mem;
	struct ttm_tt *tt;
	u32 flags;

	/* SPSC rings are hot producer/consumer control data. Keep them plain
	 * GTT; only host-read delivery buffers need coherent CPU visibility.
	 */
	flags = KFD_IOC_ALLOC_MEM_FLAGS_GTT | KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE;
	if (pages)
		flags |= KFD_IOC_ALLOC_MEM_FLAGS_COHERENT;

	mem = knod_alloc_mem(knod, size, flags);
	if (IS_ERR(mem))
		return NULL;

	if (pages) {
		tt = mem->mem->bo ? mem->mem->bo->tbo.ttm : NULL;
		if (!tt || !tt->pages) {
			knod_free_mem(knod, mem);
			return NULL;
		}
		*pages = tt->pages;
	}

	*gaddr = mem->gaddr;
	*priv = mem;
	return mem->kaddr;
}

static void knod_accel_free_mem(struct knod_dev *knodev, void *priv)
{
	struct knod_accel *accel = knodev->accel;
	struct knod *knod = accel->priv;
	struct knod_mem *mem = priv;

	knod_free_mem(knod, mem);
}

/*
 * Device->host copy primitives for the common knod_d2h_copy/knod_d2h_drain
 * path.  Thin wrappers over the SDMA engine (sdma[0]); the framework owns the
 * pending ring, fence counter and dst pool.
 */
static u32 knod_accel_d2h_submit(struct knod_dev *knodev, u64 dst, int queue,
				 u32 page_idx, u16 off, u32 len)
{
	struct knod *knod = knodev->accel->priv;
	struct knod_sdma_copy_desc c;

	/* The netmem page_pool dma_addr is the NIC address; SDMA needs
	 * the GPU VM address, so derive the source from buf[queue].
	 */
	c.src = knod->buf[queue]->gaddr + ((u64)page_idx << PAGE_SHIFT) + off;
	c.dst = dst;
	c.len = len;
	return knod_sdma_submit(knod, 0, &c, 1);
}

static void knod_accel_d2h_kick(struct knod_dev *knodev)
{
	knod_sdma_kick(knodev->accel->priv, 0);
}

static u32 knod_accel_d2h_fence(struct knod_dev *knodev, int sdma_idx)
{
	struct knod *knod = READ_ONCE(knodev->accel->priv);
	struct knod_mem *signal;

	if (!knod || sdma_idx < 0 || sdma_idx >= READ_ONCE(knod->sdma_cnt))
		return 0;
	signal = READ_ONCE(knod->sdma[sdma_idx].queue_signal);
	if (!signal || !signal->kaddr)
		return 0;

	return (u32)READ_ONCE(((struct amd_signal *)signal->kaddr)->value);
}

static int knod_accel_mp_map(struct knod_dev *knodev)
{
	struct knod *knod = knodev->accel->priv;
	int i;

	if (!knod)
		return -ENODEV;

	for (i = 0; i < knod->channels; i++)
		if (__knod_map_mem(knod, knod->buf[i]))
			knod_err(" mp_map failed ch %d\n", i);

	return 0;
}

static struct knod_accel_ops accel_ops = {
	.attach = knod_attach,
	.pre_detach = knod_pre_detach,
	.detach = knod_detach,
	.dev_start = knod_dev_start_worker,
	.dev_stop = knod_dev_stop_worker,
	.alloc_mem = knod_accel_alloc_mem,
	.free_mem = knod_accel_free_mem,
	.mp_map = knod_accel_mp_map,
	.d2h_submit = knod_accel_d2h_submit,
	.d2h_kick = knod_accel_d2h_kick,
	.d2h_fence = knod_accel_d2h_fence,
	.xdp_ops = &default_xdp_ops,
	.feature_get = knod_accel_feature_get,
	.feature_set = knod_accel_feature_set,
};

/*
 * Tear a feature down on every accel still using it before its ops pointer
 * is cleared (module unload).  Mirrors the feature_set transition to NONE.
 */
static void knod_feature_force_none(enum knod_feature feat)
{
	int i;

	for (i = 0; i < nr_accels; i++) {
		struct knod_dev *knodev;
		struct knod *knod;
		bool started;

		if (!accels[i])
			continue;
		knod = READ_ONCE(accels[i]->priv);
		knodev = knod ? READ_ONCE(accels[i]->knodev) : NULL;
		if (!knod || !knodev || knod->active_feature != feat)
			continue;
		started = READ_ONCE(knodev->started);
		if (started)
			knod_feature_stop(knod);
		knod_feature_deactivate(knod);
		knod->active_feature = KNOD_FEATURE_NONE;
		if (started)
			knod_feature_start(knod);
	}
}

void knod_accel_xdp_register(struct knod_accel_xdp_ops *xdp_ops)
{
	int i;

	/*
	 * Module load advertises the feature and sets up the permanent
	 * per-attach state (bpf_offload_dev) on already-attached accels;
	 * GPU compute resources wait for ->activate() on feature select.
	 */
	WRITE_ONCE(registered_xdp_ops, xdp_ops);
	for (i = 0; i < nr_accels; i++) {
		struct knod_dev *knodev;

		if (!accels[i])
			continue;
		knodev = READ_ONCE(accels[i]->knodev);
		if (knodev && xdp_ops->init)
			xdp_ops->init(knodev);
	}
}
EXPORT_SYMBOL(knod_accel_xdp_register);

void knod_accel_xdp_unregister(void)
{
	int i;

	/* Force any active BPF feature off, then drop the permanent state. */
	knod_feature_force_none(KNOD_FEATURE_BPF);
	for (i = 0; i < nr_accels; i++) {
		struct knod_dev *knodev;

		if (!accels[i])
			continue;
		knodev = READ_ONCE(accels[i]->knodev);
		if (knodev && registered_xdp_ops && registered_xdp_ops->exit)
			registered_xdp_ops->exit(knodev);
	}
	WRITE_ONCE(registered_xdp_ops, NULL);
}
EXPORT_SYMBOL(knod_accel_xdp_unregister);

void knod_accel_ipsec_register(struct knod_accel_ipsec_ops *ipsec_ops)
{
	/* Advertise only; resources are allocated by ->activate() on select. */
	WRITE_ONCE(accel_ops.ipsec_ops, ipsec_ops);
}
EXPORT_SYMBOL(knod_accel_ipsec_register);

void knod_accel_ipsec_unregister(void)
{
	knod_feature_force_none(KNOD_FEATURE_IPSEC);
	WRITE_ONCE(accel_ops.ipsec_ops, NULL);
}
EXPORT_SYMBOL(knod_accel_ipsec_unregister);

/*
 * Accel modules call this from their module_init before NOD attach to
 * request the minimum AQL/SDMA queue pair count their dispatcher
 * infrastructure needs. The value is a high-water mark: multiple
 * callers raise it but never lower it, so whichever module needs the
 * most queues wins.
 *
 * Must be called before knod_attach() runs - i.e. before any
 * `echo X,0 > /sys/kernel/debug/knod_dev/attach` - otherwise
 * the already-created knod context keeps its old queue_cnt and the
 * caller must unbind/rebind to pick up the new value.
 *
 * Clamped to [1, KNOD_MAX_QUEUE_CNT]. Values outside that range are ignored
 * (the internal cap can grow later without ABI break).
 */
void knod_request_queue_cnt(int n)
{
	int cur;

	if (n < 1 || n > KNOD_MAX_QUEUE_CNT)
		return;

	do {
		cur = READ_ONCE(knod_requested_queue_cnt);
		if (n <= cur)
			return;
	} while (cmpxchg(&knod_requested_queue_cnt, cur, n) != cur);
}
EXPORT_SYMBOL(knod_request_queue_cnt);

int knod_init(struct amdgpu_device *adev)
{
	int base_id = adev_to_drm(adev)->render->index * KNOD_MAX_AQL;
	struct knod_accel *accel;
	int i, n;

	n = KNOD_MAX_AQL;

	for (i = 0; i < n; i++) {
		accel = kzalloc_obj(struct knod_accel, GFP_KERNEL);
		if (!accel) {
			pr_err("knod: Failed to allocate accel node %d\n", i);
			goto err;
		}

		INIT_LIST_HEAD(&accel->list);
		accel->type = KNOD_TYPE_GPU;
		accel->accel_ops = &accel_ops;
		accel->owner = THIS_MODULE;
		accel->id = base_id + i;
		snprintf(accel->name, sizeof(accel->name), "amdgpu-%d", i);
		knod_accel_register(accel);
		accels[i] = accel;
	}
	nr_accels = n;

	return 0;

err:
	while (i-- > 0) {
		knod_accel_unregister(accels[i]);
		kfree(accels[i]);
		accels[i] = NULL;
	}
	return 0;
}

void knod_fini(struct amdgpu_device *adev)
{
	int base_id = adev_to_drm(adev)->render->index * KNOD_MAX_AQL;
	int i;

	for (i = 0; i < nr_accels; i++) {
		if (!accels[i] ||
		    accels[i]->id / KNOD_MAX_AQL != base_id / KNOD_MAX_AQL)
			continue;
		knod_accel_unregister(accels[i]);
		kfree(accels[i]);
		accels[i] = NULL;
	}
}

void knod_exit(void)
{
	struct knod *knod, *tmp;
	int i;

	for (i = 0; i < nr_accels; i++) {
		if (!accels[i])
			continue;
		knod_accel_unregister(accels[i]);
		kfree(accels[i]);
		accels[i] = NULL;
	}
	nr_accels = 0;

	list_for_each_entry_safe(knod, tmp, &ctx_list, list) {
		knod_release_ctx(knod);
	}
}
