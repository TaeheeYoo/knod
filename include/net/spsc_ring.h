/* SPDX-License-Identifier: GPL-2.0 */
/*
 * spsc_ring.h - Lock-free SPSC Ring Buffer with embedded element pool
 *
 * Single-Producer Single-Consumer ring buffer.  The ring owns a
 * contiguous page-backed memory pool.  Each slot is permanently bound
 * to a cacheline-aligned element inside that pool.
 *
 *   Producer calls spsc_produce() → receives a pointer to a free
 *   element, writes data into it, then calls spsc_produce_commit()
 *   to publish.
 *
 *   Consumer calls spsc_acquire() / spsc_pop() → receives a pointer
 *   to a filled element.  After spsc_release() the slot becomes
 *   available to the producer again - the element pointer is reused
 *   automatically because it is fixed to the slot.
 *
 * Two consumer modes (do NOT mix on the same instance):
 *
 *   Mode 1 - Sliding window (2-step consumer):
 *     spsc_produce / commit → peek → acquire → release
 *
 *   Mode 2 - Simple queue:
 *     spsc_push → pop
 *
 * Return convention:
 *   0           success
 *   -ENOSPC     ring full   (producer side)
 *   -ENOENT     ring empty  (consumer side)
 *   -EINVAL     bad parameter
 *   -ENOMEM     allocation failure
 *
 * Memory ordering:
 *   Producer: write data → smp_store_release(head)
 *   Consumer: smp_load_acquire(head) → read data
 *   Consumer: done → smp_store_release(tail)
 *   Producer: smp_load_acquire(tail) → write data
 *
 * Capacity is always a power of two.
 */

#ifndef _SPSC_RING_H
#define _SPSC_RING_H

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/log2.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/cache.h>
#include <asm/barrier.h>

struct spsc_ring {
	void		**slots;	/* pointer-per-slot into pool */
	unsigned int	mask;		/* capacity - 1 */

	/* Producer side */
	unsigned int	head;		/* next slot to publish */

	/* Consumer side */
	unsigned int	tail;		/* oldest unconsumed slot */
	unsigned int	acquired;	/* sliding window read cursor
					 *   tail <= acquired <= head
					 */

	/* Element pool */
	struct page	*pool_page;	/* compound page backing elements */
	unsigned int	pool_order;	/* page order */
	unsigned int	elem_stride;	/* cacheline-aligned element size */
} ____cacheline_aligned_in_smp;

/* ================================================================== */
/*  Init / Destroy                                                     */
/* ================================================================== */

/**
 * __spsc_init - initialize ring with a pre-allocated element pool
 * @r:         pointer to caller-allocated spsc_ring
 * @elem_size: size of each element (rounded up to cacheline)
 * @capacity:  number of elements (rounded up to power of 2)
 * @pool:      pre-allocated pool memory (must be at least stride * capacity)
 * @gfp:       allocation flags (for slots array only)
 *
 * The caller owns the pool memory; spsc_destroy will NOT free it.
 * Returns 0 on success, negative errno on failure.
 */
static inline int __spsc_init(struct spsc_ring *r, unsigned int elem_size,
			      unsigned int capacity, void *pool, gfp_t gfp)
{
	unsigned int stride = ALIGN(elem_size, SMP_CACHE_BYTES);
	unsigned int i;
	char *base = pool;

	if (elem_size == 0 || capacity == 0 || !pool)
		return -EINVAL;

	capacity = roundup_pow_of_two(capacity);

	r->slots = kcalloc(capacity, sizeof(void *), gfp);
	if (!r->slots)
		return -ENOMEM;

	for (i = 0; i < capacity; i++)
		r->slots[i] = base + (unsigned long)stride * i;

	r->mask        = capacity - 1;
	r->head        = 0;
	r->tail        = 0;
	r->acquired    = 0;
	r->pool_page   = NULL;
	r->pool_order  = 0;
	r->elem_stride = stride;

	return 0;
}

/**
 * spsc_init - allocate ring and element pool
 * @r:         pointer to caller-allocated spsc_ring
 * @elem_size: size of each element (rounded up to cacheline)
 * @capacity:  number of elements (rounded up to power of 2)
 * @gfp:       allocation flags
 *
 * Returns 0 on success, negative errno on failure.
 */
static inline int spsc_init(struct spsc_ring *r, unsigned int elem_size,
			    unsigned int capacity, gfp_t gfp)
{
	unsigned int stride = ALIGN(elem_size, SMP_CACHE_BYTES);
	unsigned long pool_bytes;
	unsigned int order;
	struct page *page;

	if (elem_size == 0 || capacity == 0)
		return -EINVAL;

	capacity = roundup_pow_of_two(capacity);
	pool_bytes = (unsigned long)stride * capacity;
	order = get_order(pool_bytes);

	if (pool_bytes > (PAGE_SIZE << order))
		return -EOVERFLOW;

	/* Allocate element pool */
	page = alloc_pages(gfp | __GFP_COMP | __GFP_ZERO, order);
	if (!page)
		return -ENOMEM;

	if (__spsc_init(r, elem_size, capacity, page_address(page), gfp)) {
		__free_pages(page, order);
		return -ENOMEM;
	}

	r->pool_page  = page;
	r->pool_order = order;

	return 0;
}

/**
 * spsc_destroy - free ring and element pool
 */
static inline void spsc_destroy(struct spsc_ring *r)
{
	if (r->pool_page) {
		__free_pages(r->pool_page, r->pool_order);
		r->pool_page = NULL;
	}
	kfree(r->slots);
	r->slots = NULL;
}

/* ================================================================== */
/*  Status helpers                                                     */
/* ================================================================== */

static inline unsigned int spsc_capacity(const struct spsc_ring *r)
{
	return r->mask + 1;
}

static inline unsigned int spsc_elem_size(const struct spsc_ring *r)
{
	return r->elem_stride;
}

/** spsc_count - total unconsumed entries (including acquired) */
static inline unsigned int spsc_count(const struct spsc_ring *r)
{
	/* acquire head so a concurrent producer's slot writes are observed */
	return smp_load_acquire(&((struct spsc_ring *)r)->head) - r->tail;
}

static inline bool spsc_empty(const struct spsc_ring *r)
{
	return spsc_count(r) == 0;
}

static inline bool spsc_full(const struct spsc_ring *r)
{
	return spsc_count(r) > r->mask;
}

/** spsc_pending - entries acquired but not yet released */
static inline unsigned int spsc_pending(const struct spsc_ring *r)
{
	return r->acquired - r->tail;
}

/* ================================================================== */
/*  Producer API  (single thread only, shared by both modes)           */
/*                                                                     */
/*  Two-phase produce:                                                 */
/*    1) spsc_produce()        → get pointer to free element           */
/*    2) caller writes data                                            */
/*    3) spsc_produce_commit() → publish to consumer                   */
/*                                                                     */
/*  Or one-shot: spsc_push() for pre-filled elements.                  */
/* ================================================================== */

/**
 * spsc_produce - reserve one slot and return its element pointer
 * @r:   ring buffer
 * @out: receives pointer to the element to write into
 *
 * The slot is NOT yet visible to the consumer.  Caller must write
 * data into *out and then call spsc_produce_commit().
 *
 * Returns 0 on success, -ENOSPC if full.
 */
static inline int spsc_produce(struct spsc_ring *r, void **out)
{
	unsigned int head = r->head;
	unsigned int tail;

	/* acquire tail to observe the slots the consumer has released */
	tail = smp_load_acquire(&r->tail);

	if (head - tail > r->mask)
		return -ENOSPC;

	*out = r->slots[head & r->mask];

	return 0;
}

/**
 * spsc_produce_commit - publish the previously reserved slot
 * @r: ring buffer
 *
 * Must be called exactly once after each successful spsc_produce().
 */
static inline void spsc_produce_commit(struct spsc_ring *r)
{
	/* wmb() (sfence on x86) is needed when the pool backing memory
	 * is mapped Write-Combining (e.g. GPU GTT).  WC stores are not
	 * ordered by x86 TSO, so smp_store_release (compiler barrier)
	 * alone cannot guarantee the element writes are visible before
	 * the head update reaches the consumer.
	 */
	wmb();
	/* release: publish the reserved slot; pairs with the head acquire */
	smp_store_release(&r->head, r->head + 1);
}

/**
 * spsc_produce_n - reserve up to @n slots
 * @r:   ring buffer
 * @out: destination array for element pointers
 * @n:   max slots to reserve
 * @cnt: out - number actually reserved (may be NULL)
 *
 * Caller must write data into each out[i] and then call
 * spsc_produce_commit_n(r, *cnt).
 *
 * Returns 0 on success, -ENOSPC if zero could be reserved.
 */
static inline int spsc_produce_n(struct spsc_ring *r, void **out,
				 unsigned int n, unsigned int *cnt)
{
	/* acquire tail to observe the slots the consumer has released */
	unsigned int tail = smp_load_acquire(&r->tail);
	unsigned int head = r->head;
	unsigned int free;
	unsigned int i;

	free = (r->mask + 1) - (head - tail);

	n = min(n, free);
	if (n == 0) {
		if (cnt)
			*cnt = 0;
		return -ENOSPC;
	}

	for (i = 0; i < n; i++)
		out[i] = r->slots[(head + i) & r->mask];

	if (cnt)
		*cnt = n;
	return 0;
}

/**
 * spsc_produce_commit_n - publish @n previously reserved slots
 * @r: ring buffer
 * @n: number of slots to publish (must match produce_n count)
 */
static inline void spsc_produce_commit_n(struct spsc_ring *r, unsigned int n)
{
	/* drain WC element stores before the head update (see commit above) */
	wmb();
	/* release: publish the reserved slots; pairs with the head acquire */
	smp_store_release(&r->head, r->head + n);
}

/* ================================================================== */
/*  Mode 1: Sliding window consumer  (single thread only)              */
/*                                                                     */
/*    peek    → read from acquired cursor, no cursor movement          */
/*    acquire → advance acquired cursor, return element pointers       */
/*    release → advance tail, slots become reusable by producer        */
/*    rewind  → reset acquired back to tail                            */
/* ================================================================== */

/**
 * spsc_peek - read element pointers from acquired cursor (read-only)
 * @r:   ring buffer
 * @out: destination array for element pointers
 * @max: max entries to peek
 * @cnt: out - number of entries peeked (may be NULL)
 *
 * Does NOT move any cursor.
 *
 * Returns 0 on success, -ENOENT if nothing to peek.
 */
static inline int spsc_peek(struct spsc_ring *r, void **out, unsigned int max,
			    unsigned int *cnt)
{
	/* acquire the producer's head; slots it published are now visible */
	unsigned int head = smp_load_acquire(&r->head);
	unsigned int acq = r->acquired;
	unsigned int avail;
	unsigned int i;

	avail = head - acq;
	avail = min(avail, max);

	if (avail == 0) {
		if (cnt)
			*cnt = 0;
		return -ENOENT;
	}

	for (i = 0; i < avail; i++)
		out[i] = r->slots[(acq + i) & r->mask];

	if (cnt)
		*cnt = avail;
	return 0;
}

/**
 * spsc_peek_at - peek starting at an offset past the acquired cursor
 * @r:    ring buffer
 * @skip: number of entries to skip past r->acquired
 * @out:  destination array for element pointers
 * @max:  max entries to peek
 * @cnt:  out - number of entries peeked (may be NULL)
 *
 * Lets the consumer stage a second batch past entries that have been
 * read by a previous peek but not yet committed via spsc_acquire.
 * Does NOT move any cursor.  The caller is responsible for tracking
 * the cumulative skip across staged batches; when those batches are
 * eventually released to the producer via spsc_acquire, pass the same
 * count so r->acquired catches up.
 *
 * Returns 0 on success, -ENOENT if nothing to peek at that offset.
 */
static inline int spsc_peek_at(struct spsc_ring *r, unsigned int skip,
			       void **out, unsigned int max, unsigned int *cnt)
{
	/* acquire the producer's head; slots it published are now visible */
	unsigned int head = smp_load_acquire(&r->head);
	unsigned int pos = r->acquired + skip;
	unsigned int avail;
	unsigned int i;

	if ((int)(head - pos) <= 0) {
		if (cnt)
			*cnt = 0;
		return -ENOENT;
	}

	avail = min(head - pos, max);
	for (i = 0; i < avail; i++)
		out[i] = r->slots[(pos + i) & r->mask];

	if (cnt)
		*cnt = avail;
	return 0;
}

/**
 * spsc_acquire - advance acquired cursor (step 1)
 * @r:   ring buffer
 * @out: destination array for element pointers, or NULL to skip
 * @max: max entries to acquire
 * @cnt: out - number acquired (may be NULL)
 *
 * Returns 0 on success, -ENOENT if nothing to acquire.
 */
static inline int spsc_acquire(struct spsc_ring *r, void **out,
			       unsigned int max, unsigned int *cnt)
{
	/* acquire the producer's head; slots it published are now visible */
	unsigned int head = smp_load_acquire(&r->head);
	unsigned int acq = r->acquired;
	unsigned int avail;
	unsigned int i;

	avail = head - acq;
	avail = min(avail, max);

	if (avail == 0) {
		if (cnt)
			*cnt = 0;
		return -ENOENT;
	}

	if (out) {
		for (i = 0; i < avail; i++)
			out[i] = r->slots[(acq + i) & r->mask];
	}

	/* Publish the window to the releasing consumer (a different CPU than
	 * this acquirer): pair with the smp_load_acquire() in spsc_release()
	 * so it cannot observe the advanced cursor before the element stores
	 * (e.g. an accel verdict) those slots now point at.
	 */
	smp_store_release(&r->acquired, acq + avail);

	if (cnt)
		*cnt = avail;
	return 0;
}

/**
 * spsc_acquire_all - acquire all available entries
 */
static inline int spsc_acquire_all(struct spsc_ring *r, void **out,
				   unsigned int *cnt)
{
	return spsc_acquire(r, out, UINT_MAX, cnt);
}

/**
 * spsc_release - get element pointers of acquired entries (release step 1)
 * @r:   ring buffer
 * @out: destination array for element pointers, or NULL to skip
 * @n:   number of entries to release (<= pending)
 * @cnt: out - number of entries prepared for release (may be NULL)
 *
 * Returns element pointers for the oldest @n acquired entries but
 * does NOT advance tail - the producer still cannot reuse these slots.
 * Caller processes the elements, then calls spsc_release_commit() to
 * actually free them.
 *
 * Returns 0 on success, -ENOENT if nothing to release.
 */
static inline int spsc_release(struct spsc_ring *r, void **out, unsigned int n,
			       unsigned int *cnt)
{
	unsigned int tail = r->tail;
	unsigned int pending;
	unsigned int i;

	/* Pairs with smp_store_release(&r->acquired) in spsc_acquire(): once
	 * we see the advanced cursor we are guaranteed to see the element
	 * stores (e.g. the accel verdict) for the slots it exposes.
	 */
	pending = smp_load_acquire(&r->acquired) - tail;

	n = min(n, pending);
	if (n == 0) {
		if (cnt)
			*cnt = 0;
		return -ENOENT;
	}

	if (out) {
		for (i = 0; i < n; i++)
			out[i] = r->slots[(tail + i) & r->mask];
	}

	if (cnt)
		*cnt = n;
	return 0;
}

/**
 * spsc_release_commit - advance tail, free slots for producer (release step 2)
 * @r: ring buffer
 * @n: number of entries to commit (must match prior spsc_release count)
 *
 * After this call the producer may reuse these slots.
 */
static inline void spsc_release_commit(struct spsc_ring *r, unsigned int n)
{
	/* release: hand the consumed slots back to the producer */
	smp_store_release(&r->tail, r->tail + n);
}

/**
 * spsc_release_all - get all acquired entries' pointers (release step 1)
 * @r:   ring buffer
 * @out: destination array for element pointers, or NULL to skip
 * @cnt: out - number of entries prepared for release (may be NULL)
 *
 * Convenience for spsc_release(r, out, pending, cnt).
 * Caller must still call spsc_release_commit(r, *cnt) afterward.
 *
 * Returns 0 on success, -ENOENT if nothing pending.
 */
static inline int spsc_release_all(struct spsc_ring *r, void **out,
				   unsigned int *cnt)
{
	return spsc_release(r, out, r->acquired - r->tail, cnt);
}

/**
 * spsc_rewind - undo acquires, reset acquired cursor to tail
 */
static inline void spsc_rewind(struct spsc_ring *r)
{
	r->acquired = r->tail;
}

/* ================================================================== */
/*  Mode 2: Simple push / pop  (single thread per side)                */
/*                                                                     */
/*  One-shot convenience wrappers.                                     */
/*  Do NOT mix with Mode 1 acquire/release on the same instance.       */
/* ================================================================== */

/**
 * spsc_push - reserve, let caller fill, and publish in one shot
 * @r:   ring buffer
 * @out: receives pointer to the element to write into
 *
 * Unlike produce/commit, the slot is published immediately.
 * Caller must fill *out BEFORE this function returns if another
 * thread could consume it - but since this is SPSC with push/pop
 * the typical pattern is:
 *
 *   spsc_push(&r, &elem);
 *   fill(elem);            // safe: consumer hasn't seen it yet?
 *
 * NO - push publishes immediately.  Use produce/commit if you need
 * to fill before publishing.  push is an alias for produce+commit.
 *
 * Returns 0 on success, -ENOSPC if full.
 */
static inline int spsc_push(struct spsc_ring *r, void **out)
{
	int ret;

	ret = spsc_produce(r, out);
	if (ret)
		return ret;

	spsc_produce_commit(r);
	return 0;
}

/**
 * spsc_pop - dequeue one element
 * @r:   ring buffer
 * @out: receives pointer to the consumed element
 *
 * The element pointer remains valid until the next spsc_push() or
 * spsc_produce() reuses that slot.
 *
 * Returns 0 on success, -ENOENT if empty.
 */
static inline int spsc_pop(struct spsc_ring *r, void **out)
{
	/* acquire the producer's head; slots it published are now visible */
	unsigned int head = smp_load_acquire(&r->head);
	unsigned int tail = r->tail;

	if (tail == head)
		return -ENOENT;

	*out = r->slots[tail & r->mask];

	r->acquired = tail + 1;
	/* release: hand the consumed slot back to the producer */
	smp_store_release(&r->tail, tail + 1);

	return 0;
}

/**
 * spsc_pop_n - dequeue up to @n elements
 * @r:   ring buffer
 * @out: destination array for element pointers
 * @n:   max entries to dequeue
 * @cnt: out - number dequeued (may be NULL)
 *
 * Returns 0 on success, -ENOENT if empty.
 */
static inline int spsc_pop_n(struct spsc_ring *r, void **out, unsigned int n,
			     unsigned int *cnt)
{
	/* acquire the producer's head; slots it published are now visible */
	unsigned int head = smp_load_acquire(&r->head);
	unsigned int tail = r->tail;
	unsigned int avail;
	unsigned int i;

	avail = head - tail;
	n = min(n, avail);

	if (n == 0) {
		if (cnt)
			*cnt = 0;
		return -ENOENT;
	}

	for (i = 0; i < n; i++)
		out[i] = r->slots[(tail + i) & r->mask];

	r->acquired = tail + n;
	/* release: hand the consumed slots back to the producer */
	smp_store_release(&r->tail, tail + n);

	if (cnt)
		*cnt = n;
	return 0;
}

#endif /* _SPSC_RING_H */
