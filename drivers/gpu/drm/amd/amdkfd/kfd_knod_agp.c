// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Host memory as the kernel's SDMA reaches it: through the AGP aperture, at
 * its start plus a page's DMA address, with nothing mapped on the GPU's side.
 * The aperture is the kernel's, VMID 0: no shader reaches host memory this
 * way.  KNOD requires it, amdgpu loaded with agp=1.
 */
#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/ioport.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include "kfd_priv.h"
#include "../amdgpu/amdgpu_ttm.h"
#include "../amdgpu/amdgpu_sdma.h"
#include "../amdgpu/amdgpu_job.h"
#include "../amdgpu/amdgpu_res_cursor.h"
#include "../amdgpu/amdgpu_amdkfd.h"
#include "kfd_knod.h"

int knod_agp_check(struct amdgpu_device *adev)
{
	if (!adev->gmc.agp_size) {
		pr_err("knod: no AGP aperture: load amdgpu with agp=1\n");
		return -EOPNOTSUPP;
	}
	return 0;
}

/* Where the kernel's SDMA reaches @len bytes at @dma, KNOD_AGP_NONE if not. */
u64 knod_agp_addr(struct amdgpu_device *adev, dma_addr_t dma, u32 len)
{
	if (dma >= adev->gmc.agp_size || len > adev->gmc.agp_size - dma)
		return KNOD_AGP_NONE;
	return adev->gmc.agp_start + dma;
}

int knod_agp_map(struct amdgpu_device *adev, struct page *page, u32 off,
		 u32 len, enum dma_data_direction dir, dma_addr_t *dma,
		 u64 *addr)
{
	*dma = dma_map_page(adev->dev, page, off, len, dir);
	if (dma_mapping_error(adev->dev, *dma))
		return -ENOMEM;
	*addr = knod_agp_addr(adev, *dma, len);
	if (*addr == KNOD_AGP_NONE) {
		dma_unmap_page(adev->dev, *dma, len, dir);
		return -ERANGE;
	}
	return 0;
}

void knod_agp_unmap(struct amdgpu_device *adev, dma_addr_t dma, u32 len,
		    enum dma_data_direction dir)
{
	dma_unmap_page(adev->dev, dma, len, dir);
}

/*
 * @skb's bytes, in order, as pieces the kernel's SDMA reaches: its linear
 * part, then each frag.  No frag list.  Undone with knod_agp_unmap_skb().
 */
int knod_agp_map_skb(struct amdgpu_device *adev, struct sk_buff *skb,
		     struct knod_skb_map *m)
{
	u32 i, len = skb_headlen(skb);
	int err;

	m->n = 0;
	if (skb_has_frag_list(skb))
		return -EOPNOTSUPP;
	if (len) {
		err = knod_agp_map(adev, virt_to_page(skb->data),
				   offset_in_page(skb->data), len,
				   DMA_TO_DEVICE, &m->seg[0].dma,
				   &m->seg[0].addr);
		if (err)
			return err;
		m->seg[m->n++].len = len;
	}
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *f = &skb_shinfo(skb)->frags[i];

		err = knod_agp_map(adev, skb_frag_page(f), skb_frag_off(f),
				   skb_frag_size(f), DMA_TO_DEVICE,
				   &m->seg[m->n].dma, &m->seg[m->n].addr);
		if (err) {
			knod_agp_unmap_skb(adev, m);
			return err;
		}
		m->seg[m->n++].len = skb_frag_size(f);
	}
	return 0;
}

void knod_agp_unmap_skb(struct amdgpu_device *adev, struct knod_skb_map *m)
{
	while (m->n) {
		m->n--;
		knod_agp_unmap(adev, m->seg[m->n].dma, m->seg[m->n].len,
			       DMA_TO_DEVICE);
	}
}

/* VMID 0's address of byte @off of a VRAM buffer, 0 if not in VRAM. */
u64 knod_vram_mc(struct amdgpu_device *adev, struct knod_mem *mem, u64 off)
{
	struct amdgpu_bo *bo = mem->mem->bo;
	struct amdgpu_res_cursor cur;

	if (bo->tbo.resource->mem_type != TTM_PL_VRAM ||
	    off >= amdgpu_bo_size(bo))
		return 0;
	amdgpu_res_first(bo->tbo.resource, off, 1, &cur);
	return adev->gmc.vram_start + cur.start;
}

/*
 * VMID 0's address of each of @pages pages of a VRAM buffer, for the
 * kernel's SDMA to write into: the buffer need not be contiguous.
 */
int knod_vram_mc_table(struct amdgpu_device *adev, struct knod_mem *mem,
		       u64 *tbl, u32 pages)
{
	struct amdgpu_bo *bo = mem->mem->bo;
	struct amdgpu_res_cursor cur;
	u32 i = 0;

	if (bo->tbo.resource->mem_type != TTM_PL_VRAM ||
	    (u64)pages << PAGE_SHIFT > amdgpu_bo_size(bo))
		return -EINVAL;
	amdgpu_res_first(bo->tbo.resource, 0, (u64)pages << PAGE_SHIFT, &cur);
	while (i < pages && cur.remaining) {
		tbl[i++] = adev->gmc.vram_start + cur.start;
		amdgpu_res_next(&cur, min_t(u64, PAGE_SIZE, cur.size));
	}
	return i == pages ? 0 : -EINVAL;
}

/*
 * One job on the kernel's SDMA, on @ent - one of the caller's own, which
 * only one thread pushes to: @copies copies and @writes dword writes, in
 * the order added, then submitted.  It may sleep: not from the TX path.
 */
int knod_ksdma_begin(struct knod_ksdma_batch *b, struct amdgpu_device *adev,
		     struct drm_sched_entity *ent, u32 copies, u32 writes)
{
	const struct amdgpu_buffer_funcs *f = adev->mman.buffer_funcs;

	if (!adev->mman.buffer_funcs_enabled)
		return -ENODEV;
	b->adev = adev;
	b->max_dw = ALIGN(copies * f->copy_num_dw + writes * 5, 8) + 8;
	return amdgpu_job_alloc_with_ib(adev, ent,
					AMDGPU_FENCE_OWNER_UNDEFINED,
					b->max_dw * 4, AMDGPU_IB_POOL_DELAYED,
					AMDGPU_KERNEL_JOB_ID_TTM_COPY_BUFFER,
					&b->job);
}

void knod_ksdma_copy(struct knod_ksdma_batch *b, u64 src, u64 dst, u32 bytes)
{
	amdgpu_emit_copy_buffer(b->adev, &b->job->ibs[0], src, dst, bytes, 0);
}

/* SDMA v5 and v6's CONSTANT_FILL, filling dwords: amdgpu's fills bytes. */
#define KNOD_SDMA_OP_CONST_FILL		11
#define KNOD_SDMA_FILL_DWORDS		(2u << 30)

/* @value to the dword at @dst, once everything added before it is done. */
void knod_ksdma_write32(struct knod_ksdma_batch *b, u64 dst, u32 value)
{
	struct amdgpu_ib *ib = &b->job->ibs[0];

	ib->ptr[ib->length_dw++] = KNOD_SDMA_OP_CONST_FILL |
				   KNOD_SDMA_FILL_DWORDS;
	ib->ptr[ib->length_dw++] = lower_32_bits(dst);
	ib->ptr[ib->length_dw++] = upper_32_bits(dst);
	ib->ptr[ib->length_dw++] = value;
	ib->ptr[ib->length_dw++] = 4 - 1;
}

struct dma_fence *knod_ksdma_submit(struct knod_ksdma_batch *b)
{
	struct amdgpu_ring *ring =
		to_amdgpu_ring(b->adev->mman.buffer_funcs_scheds[0]);

	amdgpu_ring_pad_ib(ring, &b->job->ibs[0]);
	WARN_ON(b->job->ibs[0].length_dw > b->max_dw);
	return amdgpu_job_submit(b->job);
}

void knod_ksdma_abort(struct knod_ksdma_batch *b)
{
	amdgpu_job_free(b->job);
}

static int knod_agp_ram_end(struct resource *r, void *arg)
{
	*(u64 *)arg = max_t(u64, *(u64 *)arg, r->end + 1);
	return 0;
}

/* Debug: the aperture, GART and VRAM, and whether DMA addresses are physical. */
int knod_agp_show(struct seq_file *s, struct amdgpu_device *adev)
{
	struct iommu_domain *dom = iommu_get_domain_for_dev(adev->dev);
	struct page *pg = alloc_page(GFP_KERNEL);
	dma_addr_t dma;
	u64 ram_end = 0;

	seq_printf(s, "agp   0x%llx-0x%llx size 0x%llx\n", adev->gmc.agp_start,
		   adev->gmc.agp_end, adev->gmc.agp_size);
	seq_printf(s, "gart  0x%llx-0x%llx\n", adev->gmc.gart_start,
		   adev->gmc.gart_end);
	seq_printf(s, "vram  0x%llx-0x%llx\n", adev->gmc.vram_start,
		   adev->gmc.vram_end);
	seq_printf(s, "iommu %s\n", !dom ? "none" :
		   dom->type == IOMMU_DOMAIN_IDENTITY ? "identity" :
		   dom->type == IOMMU_DOMAIN_DMA ? "dma" :
		   dom->type == IOMMU_DOMAIN_DMA_FQ ? "dma-fq" : "other");
	walk_iomem_res_desc(IORES_DESC_NONE,
			    IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY, 0, -1,
			    &ram_end, knod_agp_ram_end);
	seq_printf(s, "ram   end 0x%llx%s\n", ram_end,
		   ram_end <= adev->gmc.agp_size ? "" : " (past the aperture)");
	if (pg) {
		dma = dma_map_page(adev->dev, pg, 0, PAGE_SIZE, DMA_TO_DEVICE);
		if (!dma_mapping_error(adev->dev, dma)) {
			seq_printf(s, "page  phys 0x%llx dma 0x%llx (%s)\n",
				   (u64)page_to_phys(pg), (u64)dma,
				   dma == page_to_phys(pg) ? "same" : "differ");
			dma_unmap_page(adev->dev, dma, PAGE_SIZE,
				       DMA_TO_DEVICE);
		}
		__free_page(pg);
	}
	return 0;
}

#define KNOD_SDMA_BENCH_FRAMES	1024

static u8 knod_sdma_pattern(u32 frame, u32 byte)
{
	return (frame * 131 + byte) & 0xff;
}

/* @n frames of @bytes, host page i to VRAM page i, waited for. */
static int knod_sdma_bench_copy(struct amdgpu_device *adev,
				struct drm_sched_entity *ent, const u64 *src,
				u64 vram, u32 n, u32 bytes)
{
	struct knod_ksdma_batch b;
	struct dma_fence *fence;
	long left;
	u32 i;
	int err;

	err = knod_ksdma_begin(&b, adev, ent, n, 0);
	if (err)
		return err;
	for (i = 0; i < n; i++)
		knod_ksdma_copy(&b, src[i], vram + (u64)i * PAGE_SIZE, bytes);
	fence = knod_ksdma_submit(&b);
	left = dma_fence_wait_timeout(fence, false, msecs_to_jiffies(2000));
	dma_fence_put(fence);
	return left > 0 ? 0 : left ?: -ETIMEDOUT;
}

/* Frames of @bytes in VRAM page i that do not hold host page i's. */
static u32 knod_sdma_bench_check(void __iomem *cpu, u32 n, u32 bytes,
				 bool full)
{
	u32 i, j, bad = 0;
	u8 buf[16];

	for (i = 0; i < n; i++) {
		void __iomem *f = cpu + (size_t)i * PAGE_SIZE;
		bool ok = true;

		if (full) {
			for (j = 0; j < bytes && ok; j++)
				ok = readb(f + j) == knod_sdma_pattern(i, j);
		} else {
			memcpy_fromio(buf, f, sizeof(buf));
			for (j = 0; j < sizeof(buf) && ok; j++)
				ok = buf[j] == knod_sdma_pattern(i, j);
			ok = ok && readb(f + bytes - 1) ==
				   knod_sdma_pattern(i, bytes - 1);
			if (bytes < PAGE_SIZE)
				ok = ok && !readb(f + bytes);
		}
		bad += !ok;
	}
	return bad;
}

/*
 * Debug: host pages copied to VRAM by the kernel's SDMA through the
 * aperture, checked byte for byte first, then timed.
 */
int knod_agp_sdma_bench(struct seq_file *s, struct amdgpu_device *adev)
{
	struct drm_sched_entity *ent = NULL;
	static const u32 sizes[] = { 128, 1536, 3712 };
	u32 n = KNOD_SDMA_BENCH_FRAMES, i, j, z, bad;
	struct amdgpu_bo *bo = NULL;
	struct page **pg;
	dma_addr_t *dma;
	void *cpu = NULL;
	u64 *src, vram, t, best;
	int err = 0, r;

	pg = kcalloc(n, sizeof(*pg), GFP_KERNEL);
	dma = kcalloc(n, sizeof(*dma), GFP_KERNEL);
	src = kcalloc(n, sizeof(*src), GFP_KERNEL);
	ent = kzalloc_obj(*ent, GFP_KERNEL);
	if (!pg || !dma || !src || !ent || !adev->mman.num_buffer_funcs_scheds) {
		err = -ENOMEM;
		goto out;
	}
	/* An entity of its own: host TX pushes to its own from its thread. */
	err = drm_sched_entity_init(ent, DRM_SCHED_PRIORITY_KERNEL,
				    adev->mman.buffer_funcs_scheds, 1, NULL);
	if (err) {
		kfree(ent);
		ent = NULL;
		goto out;
	}
	for (i = 0; i < n; i++) {
		u8 *v;

		pg[i] = alloc_page(GFP_KERNEL);
		if (!pg[i]) {
			err = -ENOMEM;
			goto out;
		}
		v = page_address(pg[i]);
		for (j = 0; j < PAGE_SIZE; j++)
			v[j] = knod_sdma_pattern(i, j);
		err = knod_agp_map(adev, pg[i], 0, PAGE_SIZE, DMA_TO_DEVICE,
				   &dma[i], &src[i]);
		if (err) {
			seq_printf(s, "page %u not reachable: %d\n", i, err);
			goto out;
		}
	}
	err = amdgpu_bo_create_kernel(adev, (size_t)n * PAGE_SIZE, PAGE_SIZE,
				      AMDGPU_GEM_DOMAIN_VRAM, &bo, &vram, &cpu);
	if (err)
		goto out;

	/* First that it moves the bytes at all: eight whole pages. */
	memset_io((void __iomem *)cpu, 0, (size_t)n * PAGE_SIZE);
	err = knod_sdma_bench_copy(adev, ent, src, vram, 8, PAGE_SIZE);
	if (err)
		goto out;
	bad = knod_sdma_bench_check((void __iomem *)cpu, 8, PAGE_SIZE, true);
	seq_printf(s, "validate: %u of 8 pages match byte for byte (agp 0x%llx)\n",
		   8 - bad, adev->gmc.agp_start);
	if (bad)
		goto out;

	for (z = 0; z < ARRAY_SIZE(sizes); z++) {
		best = U64_MAX;
		for (r = 0; r < 3; r++) {
			memset_io((void __iomem *)cpu, 0, (size_t)n * PAGE_SIZE);
			t = ktime_get_ns();
			err = knod_sdma_bench_copy(adev, ent, src, vram, n, sizes[z]);
			t = ktime_get_ns() - t;
			if (err)
				goto out;
			best = min(best, t);
		}
		bad = knod_sdma_bench_check((void __iomem *)cpu, n, sizes[z],
					    false);
		seq_printf(s, "%4u B x %u: %llu ns, %llu kpps, %llu Mbps, %u bad\n",
			   sizes[z], n, best, (u64)n * 1000000 / max(best, 1ULL),
			   (u64)n * sizes[z] * 8000 / max(best, 1ULL), bad);
	}
out:
	if (bo)
		amdgpu_bo_free_kernel(&bo, &vram, &cpu);
	for (i = 0; pg && i < n && pg[i]; i++) {
		if (src && src[i])
			knod_agp_unmap(adev, dma[i], PAGE_SIZE, DMA_TO_DEVICE);
		__free_page(pg[i]);
	}
	if (ent) {
		drm_sched_entity_destroy(ent);
		kfree(ent);
	}
	kfree(src);
	kfree(dma);
	kfree(pg);
	return err;
}
