/* SPDX-License-Identifier: GPL-2.0 */
/*
 * spsc_ring.h - Lock-free single-producer single-consumer ring
 *
 * The ring owns a page-backed pool, and each slot is bound for good to a
 * cacheline-aligned element in it.  The producer reserves a slot with
 * spsc_produce(), fills the element and publishes it with
 * spsc_produce_commit().  The consumer looks at published elements with
 * spsc_peek() and hands slots back with spsc_consume().
 *
 * Memory ordering:
 *   Producer: write element -> smp_store_release(head)
 *   Consumer: smp_load_acquire(head) -> read element
 *   Consumer: done -> smp_store_release(tail)
 *   Producer: smp_load_acquire(tail) -> write element
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

/* Elements are padded to this, so a producer and a consumer working on
 * neighbouring slots do not share a line.
 */
#define SPSC_ELEM_ALIGN		SMP_CACHE_BYTES

struct spsc_ring {
	void		**slots;	/* pointer-per-slot into pool */
	unsigned int	mask;		/* capacity - 1 */
	unsigned int	head;		/* producer: next slot to publish */
	unsigned int	tail;		/* consumer: oldest unconsumed slot */
	struct page	*pool_page;	/* compound page backing elements */
	unsigned int	pool_order;
} ____cacheline_aligned_in_smp;

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
	unsigned int stride = ALIGN(elem_size, SPSC_ELEM_ALIGN);
	unsigned long pool_bytes;
	unsigned int order, i;
	struct page *page;
	char *base;

	if (elem_size == 0 || capacity == 0)
		return -EINVAL;

	capacity = roundup_pow_of_two(capacity);
	pool_bytes = (unsigned long)stride * capacity;
	order = get_order(pool_bytes);

	page = alloc_pages(gfp | __GFP_COMP | __GFP_ZERO, order);
	if (!page)
		return -ENOMEM;

	r->slots = kcalloc(capacity, sizeof(void *), gfp);
	if (!r->slots) {
		__free_pages(page, order);
		return -ENOMEM;
	}

	base = page_address(page);
	for (i = 0; i < capacity; i++)
		r->slots[i] = base + (unsigned long)stride * i;

	r->mask       = capacity - 1;
	r->head       = 0;
	r->tail       = 0;
	r->pool_page  = page;
	r->pool_order = order;

	return 0;
}

static inline void spsc_destroy(struct spsc_ring *r)
{
	if (r->pool_page) {
		__free_pages(r->pool_page, r->pool_order);
		r->pool_page = NULL;
	}
	kfree(r->slots);
	r->slots = NULL;
}

/** spsc_count - published entries not yet consumed */
static inline unsigned int spsc_count(struct spsc_ring *r)
{
	/* acquire head so a concurrent producer's element writes are seen */
	return smp_load_acquire(&r->head) - r->tail;
}

/**
 * spsc_produce - reserve one slot and return its element
 * @r:   ring buffer
 * @out: receives the element to write into
 *
 * The slot is not visible to the consumer until spsc_produce_commit().
 *
 * Returns 0 on success, -ENOSPC if full.
 */
static inline int spsc_produce(struct spsc_ring *r, void **out)
{
	unsigned int head = r->head;
	/* acquire tail to observe the slots the consumer has handed back */
	unsigned int tail = smp_load_acquire(&r->tail);

	if (head - tail > r->mask)
		return -ENOSPC;

	*out = r->slots[head & r->mask];
	return 0;
}

/** spsc_produce_commit - publish the slot the last spsc_produce() reserved */
static inline void spsc_produce_commit(struct spsc_ring *r)
{
	/* release: the element before the head that publishes it */
	smp_store_release(&r->head, r->head + 1);
}

/**
 * spsc_peek - the oldest published elements, without consuming them
 * @r:   ring buffer
 * @out: destination array for element pointers
 * @max: max entries to return
 * @cnt: out - number returned
 *
 * Returns 0 on success, -ENOENT if nothing is published.
 */
static inline int spsc_peek(struct spsc_ring *r, void **out, unsigned int max,
			    unsigned int *cnt)
{
	unsigned int tail = r->tail;
	unsigned int avail, i;

	avail = min(spsc_count(r), max);
	*cnt = avail;
	if (!avail)
		return -ENOENT;

	for (i = 0; i < avail; i++)
		out[i] = r->slots[(tail + i) & r->mask];
	return 0;
}

/** spsc_consume - hand the oldest @n peeked slots back to the producer */
static inline void spsc_consume(struct spsc_ring *r, unsigned int n)
{
	/* release: done with the elements before the producer reuses them */
	smp_store_release(&r->tail, r->tail + n);
}

#endif /* _SPSC_RING_H */
