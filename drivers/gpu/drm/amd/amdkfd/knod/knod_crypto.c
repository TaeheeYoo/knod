// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * knod_crypto: GPUs as crypto devices of their own, with no NIC.  Loading
 * it takes the GPUs listed from knod - no NIC can be attached to them until
 * the module goes - and brings up a knod context on each: its process, AQL
 * queues, memory, and the kernel's SDMA through the AGP aperture.  A
 * transform keeps to one GPU, chosen when it is made.
 */
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/idr.h>
#include <linux/kthread.h>
#include <linux/llist.h>
#include <linux/sched/task.h>
#include <crypto/chacha.h>
#include <crypto/internal/aead.h>
#include "kfd_priv.h"
#include "kfd_knod.h"
#include "knod_crypto.h"

#define KNOD_CRYPTO_MAX_GPUS	16

static int gpus[KNOD_CRYPTO_MAX_GPUS] = { 128 };
static int nr_gpus = 1;
module_param_array(gpus, int, &nr_gpus, 0444);
MODULE_PARM_DESC(gpus, "The GPUs, by render node: 128 for /dev/dri/renderD128 (default 128)");

static bool verify;
module_param(verify, bool, 0644);
MODULE_PARM_DESC(verify, "Debug: check each request's bytes in VRAM against its source");

static bool gputime = true;
module_param(gputime, bool, 0644);
MODULE_PARM_DESC(gputime, "Debug: time each batch's waves on the GPU");

static int queues = 2;
module_param(queues, int, 0444);
MODULE_PARM_DESC(queues, "AQL queues to dispatch on, each GPU");

/* Transforms' keys a GPU holds, struct knod_crypto_key each; the last the
 * kernel bench's.
 */
#define KNOD_CRYPTO_KEY_SLOTS	4096
#define KNOD_CRYPTO_BENCH_KEY	(KNOD_CRYPTO_KEY_SLOTS - 1)

/*
 * A request's place on its GPU while it is there: a slot of the work buffer
 * in VRAM for its AAD, text and tag, and its struct knod_crypto_desc in
 * GTT, which the kernel reads and writes its verdict to and the host reads
 * back.
 */
/*
 * Slots of 8 KB, a request as many in a row as it needs, aligned to their
 * number's power of two: up to 64 KB, the most an AEAD request is given.
 */
#define KNOD_CRYPTO_SLOT	SZ_8K
#define KNOD_CRYPTO_SLOTS	16384		/* 128 MB of VRAM */
#define KNOD_CRYPTO_REQ_MAX	SZ_64K
#define KNOD_CRYPTO_SLOT_PAGES	(KNOD_CRYPTO_SLOT >> PAGE_SHIFT)

/* Requests that go to the GPU together, a workgroup each. */
#define KNOD_CRYPTO_BATCH	256
/* Requests that may wait for a batch, past which they are turned away. */
#define KNOD_CRYPTO_PENDING_MAX	KNOD_CRYPTO_SLOTS
/*
 * A batch's GTT pages: the kernel's arguments then its slots, and the
 * workgroups' struct knod_crypto_time in the two after.
 */
#define KNOD_CRYPTO_ARGS_BYTES	64
#define KNOD_CRYPTO_ARGS_PAGES	3
/* Batches on a GPU at once, each at its own stage, an AQL queue each. */
#define KNOD_CRYPTO_INFLIGHT	8
#define KNOD_CRYPTO_RINGS	8

struct knod_crypto_gpu {
	struct knod *knod;
	struct dentry *dir;
	struct knod_mem *keys;	/* KNOD_CRYPTO_KEY_SLOTS of them, VRAM */
	struct ida key_ida;
	struct knod_mem *work;	/* KNOD_CRYPTO_SLOTS slots, VRAM */
	u64 *work_mc;		/* each of its pages, for the kernel's SDMA */
	struct knod_mem *descs;	/* a descriptor a slot, GTT */
	unsigned long *slot_map;	/* KNOD_CRYPTO_SLOTS, taken */
	unsigned long slot_hint;	/* where the next search starts */
	struct llist_head pending;	/* requests waiting, newest first */
	struct llist_node *backlog;	/* the worker's of them, oldest first */
	bool sleeping;		/* the worker, for a request to wake */
	atomic_t npending;	/* requests waiting for a batch */
	bool starved;		/* the oldest waits for slots to come back */
	atomic64_t busy;	/* requests turned away, the queue full */
	struct drm_sched_entity ent[KNOD_CRYPTO_RINGS];	/* the worker's */
	int nent;
	atomic64_t in_bytes, in_bad;	/* copied to VRAM, found wrong */
	atomic64_t out_bytes;		/* copied back */
	atomic64_t gpu_ok, gpu_badtag, gpu_unsup;	/* the kernel's verdicts */
	struct knod_mem *args;	/* struct knod_crypto_args, then slots, GTT */
	int nbatch;
	u64 seq, done_seq;	/* batches taken, and completed in order */
	/* Batches, their requests, and ns in each stage, summed. */
	atomic64_t batches, batch_reqs, t_in, t_kernel, t_out, t_order;
	/* Batches timed on the GPU: first start to last end, each wave's
	 * run, waves and units, summed; ticks of 10 ns.
	 */
	atomic64_t g_batches, g_span, g_wave, g_waves, g_units;
	atomic64_t g_load, g_fetch, g_crypt, g_store;	/* each wave's phases */
	struct task_struct *task;	/* the worker: batches from pending */
	struct knod_crypto_batch *batch;	/* nbatch of them */
	bool icache_inv;	/* the kernel's code not yet run */
	atomic64_t queued;	/* requests that took a slot */
	atomic64_t tfms;	/* transforms on it */
	atomic64_t reqs;	/* requests, and those the fallback took */
	atomic64_t fallback;
};

static struct knod_crypto_gpu knod_crypto_gpus[KNOD_CRYPTO_MAX_GPUS];

static struct amdgpu_device *knod_crypto_adev(struct knod_crypto_gpu *cg)
{
	return cg->knod->process->pdds[0]->dev->adev;
}
static int knod_crypto_nr;
static atomic_t knod_crypto_next;

/*
 * A transform: the GPU it keeps to, chosen in turn when it is made, and
 * the software implementation, which takes what the GPU does not.
 */
/*
 * A request's own state in its context, the fallback's subrequest last:
 * its context follows.
 */
struct knod_crypto_req {
	struct llist_node node;	/* pending, then done */
	int cpu;		/* where it was asked for, and completes */
	int err;
	struct aead_request *req;	/* the one this is the context of */
	int slot;		/* in the work buffer, -1 for none */
	int slots;		/* and how many from there */
	u32 op;			/* KNOD_CRYPTO_OP_* */
	u32 in;			/* bytes in: AAD and text, the tag to open */
	int in_nents;		/* src entries mapped for them, 0 for none */
	u32 out;		/* bytes out, to dst */
	int out_nents;		/* dst entries mapped for them, 0 for none */
	u32 status;		/* the kernel's, KNOD_CRYPTO_ST_* */
	bool sent;		/* to the kernel, in this batch */
	struct aead_request sub;
};

/* Where a batch is: free, or which stage it waits on. */
enum {
	KNOD_CRYPTO_B_FREE,
	KNOD_CRYPTO_B_IN,	/* the SDMA job into its slots */
	KNOD_CRYPTO_B_KERNEL,	/* the dispatch */
	KNOD_CRYPTO_B_OUT,	/* the SDMA job out to dst */
};

struct knod_crypto_batch {
	struct knod_crypto_gpu *cg;
	int q;			/* its AQL queue and argument page */
	int state;		/* KNOD_CRYPTO_B_* */
	u64 seq;		/* the order it was taken in */
	struct dma_fence *fence;	/* the stage's SDMA job, or NULL */
	u64 since;		/* when the stage began, ns */
	u32 kn;			/* requests the kernel took */
	u32 n;
	struct aead_request *req[KNOD_CRYPTO_BATCH];
};

/* Slot @slot's descriptor, and where its bytes are for SDMA. */
static struct knod_crypto_desc *knod_crypto_desc(struct knod_crypto_gpu *cg,
						 int slot)
{
	return (struct knod_crypto_desc *)cg->descs->kaddr + slot;
}

static u64 knod_crypto_slot_mc(struct knod_crypto_gpu *cg, int slot,
			       u32 off)
{
	return cg->work_mc[slot * KNOD_CRYPTO_SLOT_PAGES +
			   (off >> PAGE_SHIFT)] + offset_in_page(off);
}

struct knod_crypto_tfm {
	struct knod_crypto_gpu *cg;
	struct crypto_aead *fallback;
	int slot;		/* in cg's key table */
	bool keyed;
};

static struct knod_crypto_key __iomem *
knod_crypto_key_slot(struct knod_crypto_gpu *cg, int slot)
{
	return (struct knod_crypto_key __iomem *)cg->keys->kaddr + slot;
}

static void knod_crypto_key_publish(struct knod_crypto_gpu *cg)
{
	knod_hdp_flush(cg->knod);
}

static int knod_crypto_aead_init(struct crypto_aead *tfm)
{
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(tfm);
	const char *name = crypto_tfm_alg_name(crypto_aead_tfm(tfm));

	ctx->fallback = crypto_alloc_aead(name, 0, CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(ctx->fallback))
		return PTR_ERR(ctx->fallback);
	ctx->cg = &knod_crypto_gpus[(unsigned int)
		atomic_inc_return(&knod_crypto_next) % knod_crypto_nr];
	/* No slot left: the fallback takes all its requests. */
	ctx->slot = ida_alloc_max(&ctx->cg->key_ida, KNOD_CRYPTO_BENCH_KEY - 1,
				  GFP_KERNEL);
	ctx->keyed = false;
	atomic64_inc(&ctx->cg->tfms);
	crypto_aead_set_reqsize(tfm, sizeof(struct knod_crypto_req) +
				crypto_aead_reqsize(ctx->fallback));
	return 0;
}

static void knod_crypto_aead_exit(struct crypto_aead *tfm)
{
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(tfm);

	if (ctx->slot >= 0) {
		memset_io(knod_crypto_key_slot(ctx->cg, ctx->slot), 0,
			  sizeof(struct knod_crypto_key));
		knod_crypto_key_publish(ctx->cg);
		ida_free(&ctx->cg->key_ida, ctx->slot);
	}
	atomic64_dec(&ctx->cg->tfms);
	crypto_free_aead(ctx->fallback);
}

static int knod_crypto_aead_setkey(struct crypto_aead *tfm, const u8 *key,
				   unsigned int len)
{
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(tfm);
	struct knod_crypto_key k = {};
	int err;

	err = crypto_aead_setkey(ctx->fallback, key, len);
	if (err)
		return err;
	/* rfc7539esp: the ChaCha20 key, then the nonce's four-byte salt. */
	ctx->keyed = false;
	if (ctx->slot < 0 || len != CHACHA_KEY_SIZE + 4)
		return 0;
	memcpy(k.key, key, CHACHA_KEY_SIZE);
	memcpy(&k.salt, key + CHACHA_KEY_SIZE, 4);
	memcpy_toio(knod_crypto_key_slot(ctx->cg, ctx->slot), &k, sizeof(k));
	memzero_explicit(&k, sizeof(k));
	knod_crypto_key_publish(ctx->cg);
	ctx->keyed = true;
	return 0;
}

static int knod_crypto_aead_setauthsize(struct crypto_aead *tfm,
					unsigned int size)
{
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(tfm);

	return crypto_aead_setauthsize(ctx->fallback, size);
}

/*
 * The request to the fallback.  With @done, the fallback completes it
 * through knod_crypto_sub_done(), the request having taken a slot;
 * otherwise as the caller asked.
 */
static struct aead_request *knod_crypto_subreq(struct aead_request *req,
					       crypto_completion_t done)
{
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct knod_crypto_req *rctx = aead_request_ctx(req);
	struct aead_request *sub = &rctx->sub;

	atomic64_inc(&ctx->cg->fallback);
	aead_request_set_tfm(sub, ctx->fallback);
	if (done)
		aead_request_set_callback(sub, req->base.flags, done, req);
	else
		aead_request_set_callback(sub, req->base.flags,
					  req->base.complete, req->base.data);
	aead_request_set_crypt(sub, req->src, req->dst, req->cryptlen,
			       req->iv);
	aead_request_set_ad(sub, req->assoclen);
	return sub;
}

/*
 * @n slots in a row, @n a power of two and the first a multiple of it,
 * each taken with an atomic bit operation and no lock: a run another took
 * a bit of first is given back and the search goes on past it.
 */
static int knod_crypto_get_slots(struct knod_crypto_gpu *cg, int n)
{
	unsigned long start, slot, i;
	int tries;

	start = round_up(READ_ONCE(cg->slot_hint), n);
	for (tries = 0; tries < 8; tries++) {
		slot = bitmap_find_next_zero_area(cg->slot_map,
						  KNOD_CRYPTO_SLOTS, start, n,
						  n - 1);
		if (slot >= KNOD_CRYPTO_SLOTS && start) {
			start = 0;
			continue;
		}
		if (slot >= KNOD_CRYPTO_SLOTS)
			break;
		for (i = 0; i < n; i++)
			if (test_and_set_bit(slot + i, cg->slot_map))
				break;
		if (i == n) {
			WRITE_ONCE(cg->slot_hint, slot + n);
			return slot;
		}
		while (i--)
			clear_bit(slot + i, cg->slot_map);
		start = slot + n;
	}
	return -1;
}

static void knod_crypto_put_slots(struct knod_crypto_gpu *cg, int slot, int n)
{
	int i;

	for (i = 0; i < n; i++)
		clear_bit(slot + i, cg->slot_map);
	cg->starved = false;
}

/* A queued request done: its slot back, and the caller told. */
/*
 * Requests done, completed on the CPU each was asked for on, from a
 * softirq: where the user's completion expects to run - xfrm_input()
 * takes the SA's lock without disabling them - and so the stack's work
 * after it is spread as the requests were, not all on the worker.
 */
struct knod_crypto_done {
	struct llist_head list;
	struct work_struct work;
};

static DEFINE_PER_CPU(struct knod_crypto_done, knod_crypto_done);

static void knod_crypto_done_work(struct work_struct *work)
{
	struct knod_crypto_done *d = container_of(work,
						  struct knod_crypto_done,
						  work);
	struct knod_crypto_req *rctx, *next;
	struct llist_node *n;

	/* Oldest first, as they were done. */
	n = llist_reverse_order(llist_del_all(&d->list));
	llist_for_each_entry_safe(rctx, next, n, node)
		aead_request_complete(rctx->req, rctx->err);
}

static void knod_crypto_finish(struct aead_request *req, int err)
{
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct knod_crypto_req *rctx = aead_request_ctx(req);
	struct knod_crypto_done *d;
	int cpu = rctx->cpu;

	knod_crypto_put_slots(ctx->cg, rctx->slot, rctx->slots);
	rctx->slot = -1;
	rctx->err = err;
	if (!cpu_online(cpu))
		cpu = raw_smp_processor_id();
	d = per_cpu_ptr(&knod_crypto_done, cpu);
	if (llist_add(&rctx->node, &d->list))
		queue_work_on(cpu, system_bh_highpri_wq, &d->work);
}

static void knod_crypto_sub_done(void *data, int err)
{
	if (err == -EINPROGRESS)
		return;
	knod_crypto_finish(data, err);
}

/*
 * Whether @req can go to its GPU: its key is there, and its AAD, text and
 * tag fit the slots one request may have.  It takes them when a batch
 * does; until then it waits, however long the GPU is behind, instead of
 * going to the fallback: that would leave the CPUs the crypto the GPU is
 * there to take, and complete a flow's requests out of order.
 */
static bool knod_crypto_fits(struct aead_request *req, bool enc)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(tfm);
	struct knod_crypto_req *rctx = aead_request_ctx(req);
	u64 bytes = (u64)req->assoclen + req->cryptlen +
		    (enc ? crypto_aead_authsize(tfm) : 0);

	rctx->slot = -1;
	if (!ctx->keyed || bytes > KNOD_CRYPTO_REQ_MAX)
		return false;
	rctx->slots = roundup_pow_of_two(DIV_ROUND_UP(bytes, KNOD_CRYPTO_SLOT));
	rctx->in = req->assoclen + req->cryptlen;
	rctx->out = rctx->in;
	return true;
}

static int knod_crypto_queue(struct aead_request *req)
{
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct knod_crypto_req *rctx = aead_request_ctx(req);
	struct knod_crypto_gpu *cg = ctx->cg;

	/* A full queue turns away what may not wait: the caller drops it. */
	if (!(req->base.flags & CRYPTO_TFM_REQ_MAY_BACKLOG) &&
	    atomic_read(&cg->npending) >= KNOD_CRYPTO_PENDING_MAX) {
		atomic64_inc(&cg->busy);
		return -EBUSY;
	}
	atomic_inc(&cg->npending);
	rctx->req = req;
	rctx->cpu = raw_smp_processor_id();
	/* Lock-free, and a full barrier before sleeping is looked at. */
	llist_add(&rctx->node, &cg->pending);
	atomic64_inc(&cg->queued);
	if (READ_ONCE(cg->sleeping))
		wake_up_process(cg->task);
	return -EINPROGRESS;
}

/* Whether no request waits for a batch: the worker's to ask. */
static bool knod_crypto_idle(struct knod_crypto_gpu *cg)
{
	return !cg->backlog && llist_empty(&cg->pending);
}

/* Up to a batch of the pending requests, in order: how many. */
static u32 knod_crypto_take(struct knod_crypto_gpu *cg,
			    struct knod_crypto_batch *b)
{
	struct knod_crypto_req *rctx;

	b->n = 0;
	if (!cg->backlog)
		cg->backlog = llist_reverse_order(llist_del_all(&cg->pending));
	while (b->n < KNOD_CRYPTO_BATCH && cg->backlog) {
		rctx = llist_entry(cg->backlog, struct knod_crypto_req, node);
		rctx->slot = knod_crypto_get_slots(cg, rctx->slots);
		if (rctx->slot < 0) {
			cg->starved = true;
			break;
		}
		cg->backlog = cg->backlog->next;
		atomic_dec(&cg->npending);
		b->req[b->n++] = rctx->req;
	}
	return b->n;
}

/*
 * Copies of @len bytes between a mapped scatterlist and work slot @slot -
 * into the slot, or out of it @to_host - split where the slot's pages are:
 * emitted to @sb if it is there, counted either way, or -ERANGE for a
 * piece out of the aperture.
 */
static int knod_crypto_copies(struct knod_crypto_gpu *cg,
			      struct knod_ksdma_batch *sb,
			      struct scatterlist *sgl, int nents, int slot,
			      u32 len, bool to_host)
{
	struct amdgpu_device *adev = knod_crypto_adev(cg);
	struct scatterlist *sg;
	u32 off = 0, piece, n;
	dma_addr_t dma;
	int i, copies = 0;
	u64 src;

	for_each_sg(sgl, sg, nents, i) {
		dma = sg_dma_address(sg);
		n = min_t(u32, sg_dma_len(sg), len - off);
		while (n) {
			piece = min_t(u32, n, PAGE_SIZE - offset_in_page(off));
			src = knod_agp_addr(adev, dma, piece);
			if (src == KNOD_AGP_NONE)
				return -ERANGE;
			if (sb && to_host)
				knod_ksdma_copy(sb,
						knod_crypto_slot_mc(cg, slot, off),
						src, piece);
			else if (sb)
				knod_ksdma_copy(sb, src,
						knod_crypto_slot_mc(cg, slot, off),
						piece);
			dma += piece;
			off += piece;
			n -= piece;
			copies++;
		}
		if (off == len)
			break;
	}
	return copies;
}

/* Debug: whether slot @slot holds the first @len bytes of @sgl. */
static bool knod_crypto_verify(struct knod_crypto_gpu *cg,
			       struct scatterlist *sgl, int slot, u32 len)
{
	void __iomem *v = (void __iomem *)cg->work->kaddr +
			  (size_t)slot * KNOD_CRYPTO_SLOT;
	u8 a[64], b[64];
	u32 off, n;

	for (off = 0; off < len; off += n) {
		n = min_t(u32, sizeof(a), len - off);
		if (sg_pcopy_to_buffer(sgl, sg_nents(sgl), a, n, off) != n)
			return false;
		memcpy_fromio(b, v + off, n);
		if (memcmp(a, b, n))
			return false;
	}
	return true;
}

/* The worker's wake-up when an SDMA job is done: its own, freed when run. */
struct knod_crypto_wake {
	struct dma_fence_cb cb;
	struct task_struct *task;
};

static void knod_crypto_wake_cb(struct dma_fence *f, struct dma_fence_cb *cb)
{
	struct knod_crypto_wake *w = container_of(cb, struct knod_crypto_wake,
						  cb);

	wake_up_process(w->task);
	put_task_struct(w->task);
	kfree(w);
}

/*
 * The worker, which this is, woken when @f is done.  Without, it still
 * looks again in a while: see knod_crypto_wait().
 */
static void knod_crypto_wake_on(struct dma_fence *f)
{
	struct knod_crypto_wake *w = kmalloc(sizeof(*w), GFP_KERNEL);

	if (!w)
		return;
	w->task = get_task_struct(current);
	if (dma_fence_add_callback(f, &w->cb, knod_crypto_wake_cb)) {
		put_task_struct(w->task);
		kfree(w);
	}
}

/*
 * A batch's requests in: each one's source mapped and copied to its work
 * slot by one job on the kernel's SDMA, b->fence.  A request that cannot
 * be is left with in_nents 0, for the fallback alone.
 */
static void knod_crypto_in_start(struct knod_crypto_gpu *cg,
				 struct knod_crypto_batch *b)
{
	struct amdgpu_device *adev = knod_crypto_adev(cg);
	struct knod_crypto_req *rctx;
	struct knod_ksdma_batch sb;
	int copies = 0, c, nents;
	struct aead_request *req;
	u32 i;

	for (i = 0; i < b->n; i++) {
		req = b->req[i];
		rctx = aead_request_ctx(req);
		rctx->in_nents = 0;
		nents = sg_nents_for_len(req->src, rctx->in);
		if (nents <= 0 || !dma_map_sg(adev->dev, req->src, nents,
					      DMA_TO_DEVICE))
			continue;
		c = knod_crypto_copies(cg, NULL, req->src, nents, rctx->slot,
				       rctx->in, false);
		if (c < 0) {
			dma_unmap_sg(adev->dev, req->src, nents, DMA_TO_DEVICE);
			continue;
		}
		rctx->in_nents = nents;
		copies += c;
	}
	b->fence = NULL;
	b->since = ktime_get_ns();
	if (!copies || knod_ksdma_begin(&sb, adev, &cg->ent[0], copies, 0))
		return;
	for (i = 0; i < b->n; i++) {
		rctx = aead_request_ctx(b->req[i]);
		if (rctx->in_nents)
			knod_crypto_copies(cg, &sb, b->req[i]->src,
					   rctx->in_nents, rctx->slot,
					   rctx->in, false);
	}
	b->fence = knod_ksdma_submit(&sb);
	knod_crypto_wake_on(b->fence);
}

/* The batch's sources unmapped once they are in. */
static void knod_crypto_in_end(struct knod_crypto_gpu *cg,
			       struct knod_crypto_batch *b)
{
	struct amdgpu_device *adev = knod_crypto_adev(cg);
	struct knod_crypto_req *rctx;
	struct aead_request *req;
	u32 i;

	for (i = 0; i < b->n; i++) {
		req = b->req[i];
		rctx = aead_request_ctx(req);
		if (!rctx->in_nents)
			continue;
		dma_unmap_sg(adev->dev, req->src, rctx->in_nents,
			     DMA_TO_DEVICE);
		atomic64_add(rctx->in, &cg->in_bytes);
		if (READ_ONCE(verify) &&
		    !knod_crypto_verify(cg, req->src, rctx->slot, rctx->in))
			atomic64_inc(&cg->in_bad);
	}
}

/*
 * A batch's requests out: what each one's work slot holds copied to its
 * destination by one job on another of the kernel's SDMA rings than the
 * one in, b->fence.  Only the requests the kernel did.
 */
static void knod_crypto_out_start(struct knod_crypto_gpu *cg,
				  struct knod_crypto_batch *b)
{
	struct amdgpu_device *adev = knod_crypto_adev(cg);
	struct drm_sched_entity *ent = &cg->ent[cg->nent > 1 ? 1 : 0];
	struct knod_crypto_req *rctx;
	struct knod_ksdma_batch sb;
	int copies = 0, c, nents;
	struct aead_request *req;
	u32 i;

	for (i = 0; i < b->n; i++) {
		req = b->req[i];
		rctx = aead_request_ctx(req);
		rctx->out_nents = 0;
		if (rctx->status != KNOD_CRYPTO_ST_OK)
			continue;
		nents = sg_nents_for_len(req->dst, rctx->out);
		if (nents <= 0 || !dma_map_sg(adev->dev, req->dst, nents,
					      DMA_FROM_DEVICE))
			continue;
		c = knod_crypto_copies(cg, NULL, req->dst, nents, rctx->slot,
				       rctx->out, true);
		if (c < 0) {
			dma_unmap_sg(adev->dev, req->dst, nents,
				     DMA_FROM_DEVICE);
			continue;
		}
		rctx->out_nents = nents;
		copies += c;
	}
	b->fence = NULL;
	b->since = ktime_get_ns();
	if (!copies || knod_ksdma_begin(&sb, adev, ent, copies, 0))
		return;
	for (i = 0; i < b->n; i++) {
		rctx = aead_request_ctx(b->req[i]);
		if (rctx->out_nents)
			knod_crypto_copies(cg, &sb, b->req[i]->dst,
					   rctx->out_nents, rctx->slot,
					   rctx->out, true);
	}
	b->fence = knod_ksdma_submit(&sb);
	knod_crypto_wake_on(b->fence);
}

/* The batch's destinations unmapped once they are out. */
static void knod_crypto_out_end(struct knod_crypto_gpu *cg,
				struct knod_crypto_batch *b)
{
	struct amdgpu_device *adev = knod_crypto_adev(cg);
	struct knod_crypto_req *rctx;
	struct aead_request *req;
	u32 i;

	for (i = 0; i < b->n; i++) {
		req = b->req[i];
		rctx = aead_request_ctx(req);
		if (!rctx->out_nents)
			continue;
		dma_unmap_sg(adev->dev, req->dst, rctx->out_nents,
			     DMA_FROM_DEVICE);
		atomic64_add(rctx->out, &cg->out_bytes);
	}
}

/*
 * The kernel's arguments for a batch: a descriptor for each request that
 * went in, their slots in batch order, and where everything is.  Every
 * request's status starts unsupported, for the fallback if the kernel
 * leaves it.  How many requests the kernel is to take.
 */
static u32 knod_crypto_fill(struct knod_crypto_gpu *cg,
			    struct knod_crypto_batch *b)
{
	size_t off = (size_t)b->q * KNOD_CRYPTO_ARGS_PAGES * PAGE_SIZE;
	void *page = cg->args->kaddr + off;
	u32 *slots = page + KNOD_CRYPTO_ARGS_BYTES;
	struct knod_crypto_args *a = page;
	struct knod_crypto_desc *d;
	struct knod_crypto_req *rctx;
	struct knod_crypto_tfm *ctx;
	struct aead_request *req;
	struct crypto_aead *tfm;
	u32 i, n = 0, tag;

	for (i = 0; i < b->n; i++) {
		req = b->req[i];
		rctx = aead_request_ctx(req);
		rctx->status = KNOD_CRYPTO_ST_UNSUPPORTED;
		rctx->sent = false;
		tfm = crypto_aead_reqtfm(req);
		ctx = crypto_aead_ctx(tfm);
		tag = crypto_aead_authsize(tfm);
		if (!rctx->in_nents || (rctx->op == KNOD_CRYPTO_OP_DECRYPT &&
					req->cryptlen < tag))
			continue;
		d = knod_crypto_desc(cg, rctx->slot);
		d->key = ctx->slot;
		d->op = rctx->op;
		d->assoclen = req->assoclen;
		d->cryptlen = rctx->op == KNOD_CRYPTO_OP_ENCRYPT ?
			      req->cryptlen : req->cryptlen - tag;
		d->authsize = tag;
		memcpy(d->iv, req->iv, sizeof(d->iv));
		d->status = KNOD_CRYPTO_ST_UNSUPPORTED;
		rctx->out = req->assoclen + d->cryptlen +
			    (rctx->op == KNOD_CRYPTO_OP_ENCRYPT ? tag : 0);
		slots[n++] = rctx->slot;
		rctx->sent = true;
	}
	a->descs = cg->descs->gaddr;
	a->keys = cg->keys->gaddr;
	a->work = cg->work->gaddr;
	a->slots = cg->args->gaddr + off + KNOD_CRYPTO_ARGS_BYTES;
	a->times = READ_ONCE(gputime) ? cg->args->gaddr + off + PAGE_SIZE : 0;
	a->slot_bytes = KNOD_CRYPTO_SLOT;
	a->n = n;
	a->flags = cg->icache_inv ? KNOD_CRYPTO_ARGS_ICACHE_INV : 0;
	cg->icache_inv = false;
	b->kn = a->times ? n : 0;
	return n;
}

/*
 * The kernel over the @n requests knod_crypto_fill() gave it, on the
 * batch's AQL queue, not waited for.
 */
static void knod_crypto_launch(struct knod_crypto_gpu *cg,
			       struct knod_crypto_batch *b, u32 n)
{
	struct knod_mem *signal = cg->knod->kaql[b->q].queue_signal;
	struct amd_signal *sig = signal->kaddr;
	struct knod_dispatch_params p = {};

	p.workgroup_size_x = 64;
	p.grid_size_x = n * 64;
	p.grid_size_y = 1;
	p.private_segment_size = KNOD_CRYPTO_SCRATCH_BYTES;
	p.group_segment_size = KNOD_CRYPTO_LDS_BYTES;
	p.kernel_object = cg->knod->kernel->gaddr;
	p.kernarg_address = cg->args->gaddr +
			    (u64)b->q * KNOD_CRYPTO_ARGS_PAGES * PAGE_SIZE;
	WRITE_ONCE(sig->value, 1);
	/* Descriptors, slots, arguments and the armed signal before the
	 * packet that has the kernel read them.
	 */
	wmb();
	b->since = ktime_get_ns();
	knod_setup_header_signal(cg->knod, &p, b->q, signal->gaddr);
}

#define KNOD_CRYPTO_STAGE_NS	NSEC_PER_SEC

/* Debug: where the batch's kernel's time went, from what its waves wrote. */
static void knod_crypto_gputime(struct knod_crypto_gpu *cg,
				struct knod_crypto_batch *b)
{
	const struct knod_crypto_time *t = cg->args->kaddr +
		((size_t)b->q * KNOD_CRYPTO_ARGS_PAGES + 1) * PAGE_SIZE;
	s32 first = 0, last = 0, start, end;
	DECLARE_BITMAP(units, 2048);
	u64 run = 0, load = 0, fetch = 0, crypt = 0, store = 0;
	u32 i;

	if (!b->kn)
		return;
	bitmap_zero(units, 2048);
	/* Against the first's start: the counter wraps every 42 seconds. */
	for (i = 0; i < b->kn; i++) {
		start = t[i].start - t[0].start;
		end = t[i].end - t[0].start;
		first = min(first, start);
		last = max(last, end);
		run += t[i].end - t[i].start;
		load += t[i].loaded - t[i].start;
		fetch += t[i].fetched - t[i].loaded;
		crypt += t[i].sealed - t[i].fetched;
		store += t[i].end - t[i].sealed;
		__set_bit(t[i].hw_id >> 10 & 2047, units);
	}
	atomic64_inc(&cg->g_batches);
	atomic64_add(last - first, &cg->g_span);
	atomic64_add(run, &cg->g_wave);
	atomic64_add(b->kn, &cg->g_waves);
	atomic64_add(bitmap_weight(units, 2048), &cg->g_units);
	atomic64_add(load, &cg->g_load);
	atomic64_add(fetch, &cg->g_fetch);
	atomic64_add(crypt, &cg->g_crypt);
	atomic64_add(store, &cg->g_store);
}

/*
 * Whether the batch's kernel is done, and if so each request's status as
 * it left it.  One that does not finish in a second leaves them all
 * unsupported.
 */
static bool knod_crypto_kernel_done(struct knod_crypto_gpu *cg,
				    struct knod_crypto_batch *b)
{
	struct amd_signal *sig = cg->knod->kaql[b->q].queue_signal->kaddr;
	struct knod_crypto_req *rctx;
	u32 i;

	if (READ_ONCE(sig->value) > 0) {
		if (ktime_get_ns() - b->since < KNOD_CRYPTO_STAGE_NS)
			return false;
		pr_warn_ratelimited("knod_crypto: kernel over %u requests did not finish\n",
				    b->n);
		return true;
	}
	/* The kernel's verdicts after its completion. */
	rmb();
	for (i = 0; i < b->n; i++) {
		rctx = aead_request_ctx(b->req[i]);
		if (rctx->sent)
			rctx->status = READ_ONCE(knod_crypto_desc(cg,
						 rctx->slot)->status);
	}
	knod_crypto_gputime(cg, b);
	return true;
}

/* Whether the batch's SDMA job is done, or has had its second. */
static bool knod_crypto_sdma_done(struct knod_crypto_batch *b)
{
	if (!b->fence)
		return true;
	if (!dma_fence_is_signaled(b->fence)) {
		if (ktime_get_ns() - b->since < KNOD_CRYPTO_STAGE_NS)
			return false;
		pr_warn_ratelimited("knod_crypto: SDMA job over %u requests did not finish\n",
				    b->n);
	}
	dma_fence_put(b->fence);
	b->fence = NULL;
	return true;
}

/*
 * A batch's requests through: one the kernel did is done, its tag found
 * wrong -EBADMSG; any other goes to the fallback.
 */
static void knod_crypto_complete(struct knod_crypto_batch *b)
{
	struct knod_crypto_gpu *cg = b->cg;
	struct knod_crypto_req *rctx;
	struct aead_request *sub;
	u32 i;
	int err;

	for (i = 0; i < b->n; i++) {
		rctx = aead_request_ctx(b->req[i]);
		if (rctx->status == KNOD_CRYPTO_ST_OK &&
		    (rctx->out_nents || !rctx->out)) {
			atomic64_inc(&cg->gpu_ok);
			knod_crypto_finish(b->req[i], 0);
			continue;
		}
		if (rctx->status == KNOD_CRYPTO_ST_BADTAG) {
			atomic64_inc(&cg->gpu_badtag);
			knod_crypto_finish(b->req[i], -EBADMSG);
			continue;
		}
		atomic64_inc(&cg->gpu_unsup);
		sub = knod_crypto_subreq(b->req[i], knod_crypto_sub_done);
		err = rctx->op == KNOD_CRYPTO_OP_ENCRYPT ?
		      crypto_aead_encrypt(sub) : crypto_aead_decrypt(sub);
		if (err != -EINPROGRESS && err != -EBUSY)
			knod_crypto_finish(b->req[i], err);
	}
}


/*
 * A batch on as far as it can go now: whether it moved.  Batches complete
 * in the order they were taken, so a flow's requests do too.
 */
static bool knod_crypto_step(struct knod_crypto_gpu *cg,
			     struct knod_crypto_batch *b)
{
	u32 n;

	switch (b->state) {
	case KNOD_CRYPTO_B_IN:
		if (!knod_crypto_sdma_done(b))
			return false;
		atomic64_add(ktime_get_ns() - b->since, &cg->t_in);
		knod_crypto_in_end(cg, b);
		n = knod_crypto_fill(cg, b);
		if (n) {
			knod_crypto_launch(cg, b, n);
			b->state = KNOD_CRYPTO_B_KERNEL;
			return true;
		}
		knod_crypto_out_start(cg, b);
		b->state = KNOD_CRYPTO_B_OUT;
		return true;
	case KNOD_CRYPTO_B_KERNEL:
		if (!knod_crypto_kernel_done(cg, b))
			return false;
		atomic64_add(ktime_get_ns() - b->since, &cg->t_kernel);
		knod_crypto_out_start(cg, b);
		b->state = KNOD_CRYPTO_B_OUT;
		return true;
	case KNOD_CRYPTO_B_OUT:
		if (b->fence) {
			if (!knod_crypto_sdma_done(b))
				return false;
			atomic64_add(ktime_get_ns() - b->since, &cg->t_out);
			b->since = ktime_get_ns();
		}
		if (b->seq != cg->done_seq)
			return false;
		atomic64_add(ktime_get_ns() - b->since, &cg->t_order);
		knod_crypto_out_end(cg, b);
		knod_crypto_complete(b);
		cg->done_seq++;
		b->state = KNOD_CRYPTO_B_FREE;
		return true;
	}
	return false;
}

/*
 * Every batch on, a free one taking what is pending: whether any is out,
 * and in @moved whether any moved.
 */
static bool knod_crypto_pump(struct knod_crypto_gpu *cg, bool take,
			     bool *moved)
{
	struct knod_crypto_batch *b;
	bool busy = false;
	int i;

	*moved = false;
	for (i = 0; i < cg->nbatch; i++) {
		b = &cg->batch[i];
		while (knod_crypto_step(cg, b))
			*moved = true;
		if (b->state == KNOD_CRYPTO_B_FREE && take &&
		    knod_crypto_take(cg, b)) {
			b->seq = cg->seq++;
			atomic64_inc(&cg->batches);
			atomic64_add(b->n, &cg->batch_reqs);
			knod_crypto_in_start(cg, b);
			b->state = KNOD_CRYPTO_B_IN;
			*moved = true;
		}
		busy |= b->state != KNOD_CRYPTO_B_FREE;
	}
	return busy;
}

/* Whether any batch can move on now. */
static bool knod_crypto_ready(struct knod_crypto_gpu *cg)
{
	struct knod_crypto_batch *b;
	struct amd_signal *sig;
	int i;

	for (i = 0; i < cg->nbatch; i++) {
		b = &cg->batch[i];
		switch (b->state) {
		case KNOD_CRYPTO_B_FREE:
			if (!knod_crypto_idle(cg) && !cg->starved)
				return true;
			break;
		case KNOD_CRYPTO_B_KERNEL:
			sig = cg->knod->kaql[b->q].queue_signal->kaddr;
			if (READ_ONCE(sig->value) <= 0)
				return true;
			break;
		case KNOD_CRYPTO_B_OUT:
			if (b->seq != cg->done_seq)
				break;
			fallthrough;
		case KNOD_CRYPTO_B_IN:
			if (!b->fence || dma_fence_is_signaled(b->fence))
				return true;
			break;
		}
	}
	return false;
}

/*
 * Waiting on the batches out, asleep: an SDMA job's callback or a request
 * wakes the worker.  A dispatch's completion has none, so with a kernel
 * out it looks again soon; without, now and then, for the stages' timeouts.
 */
#define KNOD_CRYPTO_KERNEL_POLL_NS	(10 * NSEC_PER_USEC)
#define KNOD_CRYPTO_IDLE_POLL_NS	NSEC_PER_MSEC

static void knod_crypto_wait(struct knod_crypto_gpu *cg)
{
	ktime_t t = KNOD_CRYPTO_IDLE_POLL_NS;
	int i;

	for (i = 0; i < cg->nbatch; i++)
		if (cg->batch[i].state == KNOD_CRYPTO_B_KERNEL)
			t = KNOD_CRYPTO_KERNEL_POLL_NS;
	set_current_state(TASK_INTERRUPTIBLE);
	WRITE_ONCE(cg->sleeping, true);
	/* Against a request added after the look below. */
	smp_mb();
	if (!knod_crypto_ready(cg) && !kthread_should_stop())
		schedule_hrtimeout_range(&t, t / 4, HRTIMER_MODE_REL);
	WRITE_ONCE(cg->sleeping, false);
	__set_current_state(TASK_RUNNING);
}

#define KNOD_CRYPTO_SPIN_NS	(20 * NSEC_PER_USEC)

/*
 * The worker, a thread a GPU: up to nbatch batches out at once, each at its
 * own stage, while there are any; a short spin for more, then sleep until
 * a request wakes it.  Whatever is out when it stops is seen through.
 */
static int knod_crypto_thread(void *data)
{
	struct knod_crypto_gpu *cg = data;
	bool moved;
	u64 until;

	while (!kthread_should_stop()) {
		if (knod_crypto_pump(cg, true, &moved)) {
			if (!moved)
				knod_crypto_wait(cg);
			continue;
		}
		until = ktime_get_ns() + KNOD_CRYPTO_SPIN_NS;
		while (knod_crypto_idle(cg) && ktime_get_ns() < until &&
		       !kthread_should_stop())
			cpu_relax();
		set_current_state(TASK_INTERRUPTIBLE);
		WRITE_ONCE(cg->sleeping, true);
		/* Against a request added after the look below. */
		smp_mb();
		if (knod_crypto_idle(cg) && !kthread_should_stop())
			schedule();
		WRITE_ONCE(cg->sleeping, false);
		__set_current_state(TASK_RUNNING);
	}
	while (knod_crypto_pump(cg, false, &moved))
		if (!moved)
			knod_crypto_wait(cg);
	return 0;
}

static int knod_crypto_aead_encrypt(struct aead_request *req)
{
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct knod_crypto_req *rctx = aead_request_ctx(req);

	atomic64_inc(&ctx->cg->reqs);
	if (!knod_crypto_fits(req, true))
		return crypto_aead_encrypt(knod_crypto_subreq(req, NULL));
	rctx->op = KNOD_CRYPTO_OP_ENCRYPT;
	return knod_crypto_queue(req);
}

static int knod_crypto_aead_decrypt(struct aead_request *req)
{
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct knod_crypto_req *rctx = aead_request_ctx(req);

	atomic64_inc(&ctx->cg->reqs);
	if (!knod_crypto_fits(req, false))
		return crypto_aead_decrypt(knod_crypto_subreq(req, NULL));
	rctx->op = KNOD_CRYPTO_OP_DECRYPT;
	return knod_crypto_queue(req);
}

static struct aead_alg knod_crypto_algs[] = {
	{
		.base = {
			.cra_name = "rfc7539esp(chacha20,poly1305)",
			.cra_driver_name = "rfc7539esp-chacha20-poly1305-knod",
			.cra_priority = 600,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_NEED_FALLBACK,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct knod_crypto_tfm),
			.cra_module = THIS_MODULE,
		},
		.init = knod_crypto_aead_init,
		.exit = knod_crypto_aead_exit,
		.setkey = knod_crypto_aead_setkey,
		.setauthsize = knod_crypto_aead_setauthsize,
		.encrypt = knod_crypto_aead_encrypt,
		.decrypt = knod_crypto_aead_decrypt,
		.ivsize = 8,
		.maxauthsize = 16,
		.chunksize = 64,
	},
};

static int knod_crypto_stats_show(struct seq_file *s, void *unused)
{
	struct knod_crypto_gpu *cg = s->private;

	seq_printf(s, "busy %lld pending %d\n", atomic64_read(&cg->busy),
		   atomic_read(&cg->npending));
	seq_printf(s, "tfms %lld requests %lld queued %lld fallback %lld\n",
		   atomic64_read(&cg->tfms), atomic64_read(&cg->reqs),
		   atomic64_read(&cg->queued), atomic64_read(&cg->fallback));
	seq_printf(s, "in %lld bytes, %lld requests wrong (verify %s); out %lld bytes\n",
		   atomic64_read(&cg->in_bytes), atomic64_read(&cg->in_bad),
		   READ_ONCE(verify) ? "on" : "off",
		   atomic64_read(&cg->out_bytes));
	seq_printf(s, "batches %lld requests %lld; ns in %lld kernel %lld out %lld order %lld\n",
		   atomic64_read(&cg->batches), atomic64_read(&cg->batch_reqs),
		   atomic64_read(&cg->t_in), atomic64_read(&cg->t_kernel),
		   atomic64_read(&cg->t_out), atomic64_read(&cg->t_order));
	seq_printf(s, "gpu: batches %lld waves %lld; ticks span %lld wave %lld; units %lld\n",
		   atomic64_read(&cg->g_batches), atomic64_read(&cg->g_waves),
		   atomic64_read(&cg->g_span), atomic64_read(&cg->g_wave),
		   atomic64_read(&cg->g_units));
	seq_printf(s, "gpu: wave ticks load %lld fetch %lld crypt %lld store %lld\n",
		   atomic64_read(&cg->g_load), atomic64_read(&cg->g_fetch),
		   atomic64_read(&cg->g_crypt), atomic64_read(&cg->g_store));
	seq_printf(s, "kernel: ok %lld badtag %lld unsupported %lld\n",
		   atomic64_read(&cg->gpu_ok), atomic64_read(&cg->gpu_badtag),
		   atomic64_read(&cg->gpu_unsup));
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(knod_crypto_stats);

/*
 * Debug: the kernel alone, no copies.  For each size, as many requests of
 * it as a dispatch takes and the work buffer holds, sealed in place again
 * and again for 20 ms, whatever the slots hold.  With no traffic: it uses
 * batch 0's queue and arguments and the slots' descriptors.
 */
#define KNOD_CRYPTO_BENCH_NS	(20 * NSEC_PER_MSEC)

static int knod_crypto_compute_bench_show(struct seq_file *s, void *unused)
{
	static const u32 sizes[] = { 64, 256, 1024, 1420, 4096, 8192, 16384,
				     65536, 262144, 1048576 };
	struct knod_crypto_gpu *cg = s->private;
	struct knod_crypto_batch *b = &cg->batch[0];
	struct knod_crypto_args *a = cg->args->kaddr;
	u32 *slots = cg->args->kaddr + KNOD_CRYPTO_ARGS_BYTES;
	struct knod_crypto_key __iomem *key;
	u32 i, z, n, per, reps, bad;
	struct knod_crypto_desc *d;
	u64 t0, ns;

	for (i = 0; i < cg->nbatch; i++)
		if (cg->batch[i].state != KNOD_CRYPTO_B_FREE)
			return -EBUSY;
	key = knod_crypto_key_slot(cg, KNOD_CRYPTO_BENCH_KEY);
	memset_io(key, 0x5a, sizeof(*key));
	writel(0, &key->rounds);
	knod_crypto_key_publish(cg);
	b->n = 0;
	b->kn = 0;
	seq_puts(s, "bytes      requests  us/dispatch  GB/s\n");
	for (z = 0; z < ARRAY_SIZE(sizes); z++) {
		per = DIV_ROUND_UP(sizes[z] + 40, KNOD_CRYPTO_SLOT);
		n = min_t(u32, KNOD_CRYPTO_BATCH, KNOD_CRYPTO_SLOTS / per);
		for (i = 0; i < n; i++) {
			d = knod_crypto_desc(cg, i * per);
			d->key = KNOD_CRYPTO_BENCH_KEY;
			d->op = KNOD_CRYPTO_OP_ENCRYPT;
			d->assoclen = 16;
			d->cryptlen = sizes[z];
			d->authsize = 16;
			d->iv[0] = i;
			d->iv[1] = z;
			d->status = KNOD_CRYPTO_ST_UNSUPPORTED;
			slots[i] = i * per;
		}
		a->descs = cg->descs->gaddr;
		a->keys = cg->keys->gaddr;
		a->work = cg->work->gaddr;
		a->slots = cg->args->gaddr + KNOD_CRYPTO_ARGS_BYTES;
		a->slot_bytes = KNOD_CRYPTO_SLOT;
		a->n = n;
		a->times = 0;
		a->flags = cg->icache_inv ? KNOD_CRYPTO_ARGS_ICACHE_INV : 0;
		cg->icache_inv = false;
		/* Once to warm up, then as many as 20 ms take. */
		knod_crypto_launch(cg, b, n);
		while (!knod_crypto_kernel_done(cg, b))
			cpu_relax();
		a->flags = 0;
		reps = 0;
		t0 = ktime_get_ns();
		do {
			knod_crypto_launch(cg, b, n);
			while (!knod_crypto_kernel_done(cg, b))
				cpu_relax();
			reps++;
			ns = ktime_get_ns() - t0;
		} while (ns < KNOD_CRYPTO_BENCH_NS);
		for (i = 0, bad = 0; i < n; i++)
			bad += READ_ONCE(knod_crypto_desc(cg, i * per)->status) !=
			       KNOD_CRYPTO_ST_OK;
		seq_printf(s, "%-10u %-9u %-12llu %llu.%02llu%s\n", sizes[z], n,
			   div_u64(ns, reps * NSEC_PER_USEC),
			   div64_u64((u64)n * sizes[z] * reps, ns),
			   div64_u64((u64)n * sizes[z] * reps * 100, ns) % 100,
			   bad ? " (not done)" : "");
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(knod_crypto_compute_bench);

static int knod_crypto_aperture_show(struct seq_file *s, void *unused)
{
	return knod_agp_show(s, knod_crypto_adev(s->private));
}
DEFINE_SHOW_ATTRIBUTE(knod_crypto_aperture);

static int knod_crypto_sdma_bench_show(struct seq_file *s, void *unused)
{
	return knod_agp_sdma_bench(s, knod_crypto_adev(s->private));
}
DEFINE_SHOW_ATTRIBUTE(knod_crypto_sdma_bench);

static int knod_crypto_dispatch_bench_show(struct seq_file *s, void *unused)
{
	struct knod_crypto_gpu *cg = s->private;

	return knod_dispatch_bench(s, cg->knod, 0);
}
DEFINE_SHOW_ATTRIBUTE(knod_crypto_dispatch_bench);

/*
 * The crypto kernel from the core blob, at the context's kernel object,
 * and the buffer its arguments and each batch's slots go in.
 */
static int knod_crypto_kernel_init(struct knod_crypto_gpu *cg)
{
	const u32 *code;
	struct knod_mem *mem;
	u32 size;
	int err;

	BUILD_BUG_ON(sizeof(struct knod_crypto_args) > KNOD_CRYPTO_ARGS_BYTES);
	code = knod_blob_find(&cg->knod->core_blob, KNOD_BLOB_CRYPTO_KERNEL, 0,
			      &size);
	if (!code) {
		pr_err("knod_crypto: the core blob has no crypto kernel\n");
		return -ENOENT;
	}
	err = knod_kernel_install(cg->knod, code, size);
	if (err)
		return err;
	cg->icache_inv = true;
	BUILD_BUG_ON(KNOD_CRYPTO_ARGS_BYTES + KNOD_CRYPTO_BATCH * sizeof(u32) >
		     PAGE_SIZE);
	cg->nbatch = min(cg->knod->queue_cnt, KNOD_CRYPTO_INFLIGHT);
	BUILD_BUG_ON(KNOD_CRYPTO_BATCH * sizeof(struct knod_crypto_time) >
		     (KNOD_CRYPTO_ARGS_PAGES - 1) * PAGE_SIZE);
	mem = knod_alloc_mem(cg->knod, (size_t)cg->nbatch *
			     KNOD_CRYPTO_ARGS_PAGES * PAGE_SIZE,
			     KFD_IOC_ALLOC_MEM_FLAGS_GTT |
			     KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
			     KFD_IOC_ALLOC_MEM_FLAGS_COHERENT);
	if (IS_ERR(mem))
		return PTR_ERR(mem);
	cg->args = mem;
	memset(mem->kaddr, 0, mem->size);
	return 0;
}

/* The work buffer, its pages' SDMA addresses, and the descriptors. */
static int knod_crypto_work_init(struct knod_crypto_gpu *cg)
{
	u32 pages = KNOD_CRYPTO_SLOTS * KNOD_CRYPTO_SLOT_PAGES;
	struct knod_mem *mem;

	cg->slot_map = bitmap_zalloc(KNOD_CRYPTO_SLOTS, GFP_KERNEL);
	if (!cg->slot_map)
		return -ENOMEM;
	mem = knod_alloc_mem(cg->knod, (size_t)KNOD_CRYPTO_SLOTS *
			     KNOD_CRYPTO_SLOT, KFD_IOC_ALLOC_MEM_FLAGS_VRAM |
			     KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE);
	if (IS_ERR(mem))
		return PTR_ERR(mem);
	cg->work = mem;
	cg->work_mc = kvmalloc_array(pages, sizeof(u64), GFP_KERNEL);
	if (!cg->work_mc)
		return -ENOMEM;
	if (knod_vram_mc_table(knod_crypto_adev(cg), cg->work, cg->work_mc,
			       pages))
		return -EINVAL;
	mem = knod_alloc_mem(cg->knod, KNOD_CRYPTO_SLOTS *
			     sizeof(struct knod_crypto_desc),
			     KFD_IOC_ALLOC_MEM_FLAGS_GTT |
			     KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
			     KFD_IOC_ALLOC_MEM_FLAGS_COHERENT);
	if (IS_ERR(mem))
		return PTR_ERR(mem);
	cg->descs = mem;
	memset(cg->descs->kaddr, 0, cg->descs->size);
	return 0;
}

static void knod_crypto_put_all(void)
{
	struct knod_crypto_gpu *cg;

	while (knod_crypto_nr) {
		cg = &knod_crypto_gpus[--knod_crypto_nr];
		debugfs_remove_recursive(cg->dir);
		if (cg->task)
			kthread_stop(cg->task);
		cg->task = NULL;
		kvfree(cg->batch);
		cg->batch = NULL;
		knod_ksdma_entities_fini(cg->ent, cg->nent);
		cg->nent = 0;
		if (cg->keys)
			knod_free_mem(cg->knod, cg->keys);
		if (cg->args)
			knod_free_mem(cg->knod, cg->args);
		if (cg->descs)
			knod_free_mem(cg->knod, cg->descs);
		if (cg->work)
			knod_free_mem(cg->knod, cg->work);
		kvfree(cg->work_mc);
		bitmap_free(cg->slot_map);
		cg->slot_map = NULL;
		ida_destroy(&cg->key_ida);
		knod_standalone_put(cg->knod);
	}
}

/* The completions the workers handed on, run before the module goes. */
static void knod_crypto_flush_done(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		flush_work(&per_cpu_ptr(&knod_crypto_done, cpu)->work);
}

static int __init knod_crypto_init(void)
{
	struct knod_crypto_done *d;
	struct knod_crypto_gpu *cg;
	int i, j, err;

	for_each_possible_cpu(i) {
		d = per_cpu_ptr(&knod_crypto_done, i);
		init_llist_head(&d->list);
		INIT_WORK(&d->work, knod_crypto_done_work);
	}
	for (i = 0; i < nr_gpus; i++) {
		cg = &knod_crypto_gpus[knod_crypto_nr];
		cg->knod = knod_standalone_get(gpus[i], queues);
		if (IS_ERR(cg->knod)) {
			err = PTR_ERR(cg->knod);
			pr_err("knod_crypto: GPU %d: %d\n", gpus[i], err);
			knod_crypto_put_all();
			return err;
		}
		ida_init(&cg->key_ida);
		init_llist_head(&cg->pending);

		cg->keys = knod_alloc_mem(cg->knod, KNOD_CRYPTO_KEY_SLOTS *
					  sizeof(struct knod_crypto_key),
					  KFD_IOC_ALLOC_MEM_FLAGS_VRAM |
					  KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE);
		if (IS_ERR(cg->keys)) {
			err = PTR_ERR(cg->keys);
			cg->keys = NULL;
			knod_crypto_nr++;
			knod_crypto_put_all();
			return err;
		}
		memset_io((void __iomem *)cg->keys->kaddr, 0, cg->keys->size);
		knod_crypto_key_publish(cg);
		err = knod_crypto_work_init(cg);
		if (!err)
			err = knod_crypto_kernel_init(cg);
		if (!err) {
			cg->nent = knod_ksdma_entities_init(knod_crypto_adev(cg),
							    cg->ent,
							    KNOD_CRYPTO_RINGS);
			err = cg->nent < 0 ? cg->nent : 0;
			if (err)
				cg->nent = 0;
		}
		if (!err) {
			cg->batch = kvcalloc(cg->nbatch, sizeof(*cg->batch),
					     GFP_KERNEL);
			err = cg->batch ? 0 : -ENOMEM;
		}
		for (j = 0; !err && j < cg->nbatch; j++) {
			cg->batch[j].cg = cg;
			cg->batch[j].q = j;
		}
		if (!err) {
			cg->task = kthread_run(knod_crypto_thread, cg,
					       "knod_crypto/%d", gpus[i]);
			if (IS_ERR(cg->task)) {
				err = PTR_ERR(cg->task);
				cg->task = NULL;
			}
		}
		if (err) {
			knod_crypto_nr++;
			knod_crypto_put_all();
			return err;
		}
		sched_set_fifo_low(cg->task);
		/* dri/<N>/knod/crypto/, beside what the context put there. */
		cg->dir = debugfs_create_dir("crypto", cg->knod->debug_dir);
		debugfs_create_file("aperture", 0400, cg->dir, cg,
				    &knod_crypto_aperture_fops);
		debugfs_create_file("sdma_bench", 0400, cg->dir, cg,
				    &knod_crypto_sdma_bench_fops);
		debugfs_create_file("compute_bench", 0400, cg->dir, cg,
				    &knod_crypto_compute_bench_fops);
		debugfs_create_file("dispatch_bench", 0400, cg->dir, cg,
				    &knod_crypto_dispatch_bench_fops);
		debugfs_create_file("stats", 0444, cg->dir, cg,
				    &knod_crypto_stats_fops);
		knod_crypto_nr++;
		pr_info("knod_crypto: GPU %d, %d queues\n", gpus[i], queues);
	}
	/* The GPUs up first: a transform made from now on takes one. */
	err = crypto_register_aeads(knod_crypto_algs,
				    ARRAY_SIZE(knod_crypto_algs));
	if (err) {
		pr_err("knod_crypto: algorithms not registered: %d\n", err);
		knod_crypto_put_all();
	}
	return err;
}

static void __exit knod_crypto_exit(void)
{
	/* No transform is left once the algorithms go: the module's own
	 * references hold it until then.
	 */
	crypto_unregister_aeads(knod_crypto_algs, ARRAY_SIZE(knod_crypto_algs));
	knod_crypto_put_all();
	knod_crypto_flush_done();
}

module_init(knod_crypto_init);
module_exit(knod_crypto_exit);

MODULE_DESCRIPTION("KNOD: GPUs as crypto devices of their own");
MODULE_LICENSE("GPL");
