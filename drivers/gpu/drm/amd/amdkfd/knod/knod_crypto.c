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

static int queues = 2;
module_param(queues, int, 0444);
MODULE_PARM_DESC(queues, "AQL queues to dispatch on, each GPU");

/* Transforms' keys a GPU holds, struct knod_crypto_key each. */
#define KNOD_CRYPTO_KEY_SLOTS	4096

/*
 * A request's place on its GPU while it is there: a slot of the work buffer
 * in VRAM for its AAD, text and tag, and its struct knod_crypto_desc in
 * GTT, which the kernel reads and writes its verdict to and the host reads
 * back.
 */
#define KNOD_CRYPTO_SLOT	SZ_64K
#define KNOD_CRYPTO_SLOTS	2048		/* 128 MB of VRAM */
#define KNOD_CRYPTO_SLOT_PAGES	(KNOD_CRYPTO_SLOT >> PAGE_SHIFT)

/* Requests that go to the GPU together, a workgroup each. */
#define KNOD_CRYPTO_BATCH	256
#define KNOD_CRYPTO_RINGS	8

struct knod_crypto_gpu {
	struct knod *knod;
	struct dentry *dir;
	struct knod_mem *keys;	/* KNOD_CRYPTO_KEY_SLOTS of them, VRAM */
	struct ida key_ida;
	struct knod_mem *work;	/* KNOD_CRYPTO_SLOTS slots, VRAM */
	u64 *work_mc;		/* each of its pages, for the kernel's SDMA */
	struct knod_mem *descs;	/* a descriptor a slot, GTT */
	struct ida slot_ida;
	spinlock_t lock;	/* pending */
	struct list_head pending;	/* requests waiting for a batch */
	struct drm_sched_entity ent[KNOD_CRYPTO_RINGS];	/* the worker's */
	int nent;
	atomic64_t in_bytes, in_bad;	/* copied to VRAM, found wrong */
	atomic64_t out_bytes, out_bad;	/* copied back, found wrong */
	struct task_struct *task;	/* the worker: batches from pending */
	struct knod_crypto_batch *batch;	/* the worker's */
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
	struct list_head node;
	struct aead_request *req;	/* the one this is the context of */
	int slot;		/* in the work buffer, -1 for none */
	u32 op;			/* KNOD_CRYPTO_OP_* */
	u32 in;			/* bytes in: AAD and text, the tag to open */
	int in_nents;		/* src entries mapped for them, 0 for none */
	u32 out;		/* bytes out, to dst */
	int out_nents;		/* dst entries mapped for them, 0 for none */
	struct aead_request sub;
};

struct knod_crypto_batch {
	struct knod_crypto_gpu *cg;
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
	/* Written through the BAR: out of the HDP before a shader reads it. */
	wmb();
	amdgpu_device_flush_hdp(knod_crypto_adev(cg), NULL);
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
	ctx->slot = ida_alloc_max(&ctx->cg->key_ida, KNOD_CRYPTO_KEY_SLOTS - 1,
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

/* A queued request done: its slot back, and the caller told. */
static void knod_crypto_finish(struct aead_request *req, int err)
{
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct knod_crypto_req *rctx = aead_request_ctx(req);

	ida_free(&ctx->cg->slot_ida, rctx->slot);
	rctx->slot = -1;
	aead_request_complete(req, err);
}

static void knod_crypto_sub_done(void *data, int err)
{
	if (err == -EINPROGRESS)
		return;
	knod_crypto_finish(data, err);
}

/*
 * Whether @req goes to its GPU: its key is there, its AAD, text and tag
 * fit a slot, and a slot is free - which it then holds.
 */
static bool knod_crypto_take_slot(struct aead_request *req, bool enc)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(tfm);
	struct knod_crypto_req *rctx = aead_request_ctx(req);
	u64 bytes = (u64)req->assoclen + req->cryptlen +
		    (enc ? crypto_aead_authsize(tfm) : 0);
	int slot;

	rctx->slot = -1;
	if (!ctx->keyed || bytes > KNOD_CRYPTO_SLOT)
		return false;
	slot = ida_alloc_max(&ctx->cg->slot_ida, KNOD_CRYPTO_SLOTS - 1,
			     GFP_ATOMIC);
	if (slot < 0)
		return false;
	rctx->slot = slot;
	rctx->in = req->assoclen + req->cryptlen;
	rctx->out = rctx->in;
	return true;
}

static int knod_crypto_queue(struct aead_request *req)
{
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct knod_crypto_req *rctx = aead_request_ctx(req);
	struct knod_crypto_gpu *cg = ctx->cg;

	rctx->req = req;
	spin_lock_bh(&cg->lock);
	list_add_tail(&rctx->node, &cg->pending);
	spin_unlock_bh(&cg->lock);
	atomic64_inc(&cg->queued);
	wake_up_process(cg->task);
	return -EINPROGRESS;
}

/* Up to a batch of the pending requests, in order: how many. */
static u32 knod_crypto_take(struct knod_crypto_gpu *cg,
			    struct knod_crypto_batch *b)
{
	struct knod_crypto_req *rctx;

	b->n = 0;
	spin_lock_bh(&cg->lock);
	while (b->n < KNOD_CRYPTO_BATCH &&
	       (rctx = list_first_entry_or_null(&cg->pending,
						struct knod_crypto_req, node))) {
		list_del(&rctx->node);
		b->req[b->n++] = rctx->req;
	}
	spin_unlock_bh(&cg->lock);
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

/*
 * A batch's requests in: each one's source mapped and copied to its work
 * slot by one job on the kernel's SDMA, waited for.  A request that cannot
 * be is left with in_nents 0, for the fallback alone.
 */
static void knod_crypto_in(struct knod_crypto_gpu *cg,
			   struct knod_crypto_batch *b)
{
	struct amdgpu_device *adev = knod_crypto_adev(cg);
	struct knod_crypto_req *rctx;
	struct knod_ksdma_batch sb;
	struct dma_fence *fence;
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
	if (!copies || knod_ksdma_begin(&sb, adev, &cg->ent[0], copies, 0))
		goto unmap;
	for (i = 0; i < b->n; i++) {
		rctx = aead_request_ctx(b->req[i]);
		if (rctx->in_nents)
			knod_crypto_copies(cg, &sb, b->req[i]->src,
					   rctx->in_nents, rctx->slot,
					   rctx->in, false);
	}
	fence = knod_ksdma_submit(&sb);
	dma_fence_wait_timeout(fence, false, msecs_to_jiffies(1000));
	dma_fence_put(fence);
unmap:
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

/* Debug: whether @a and @b hold the same first @len bytes. */
static bool knod_crypto_same(struct scatterlist *a, struct scatterlist *b,
			     u32 len)
{
	u8 x[64], y[64];
	u32 off, n;

	for (off = 0; off < len; off += n) {
		n = min_t(u32, sizeof(x), len - off);
		if (sg_pcopy_to_buffer(a, sg_nents(a), x, n, off) != n ||
		    sg_pcopy_to_buffer(b, sg_nents(b), y, n, off) != n ||
		    memcmp(x, y, n))
			return false;
	}
	return true;
}

/*
 * A batch's requests out: what each one's work slot holds copied to its
 * destination by one job on the kernel's SDMA, waited for.  Only the
 * requests that went in.
 */
static void knod_crypto_out(struct knod_crypto_gpu *cg,
			    struct knod_crypto_batch *b)
{
	struct amdgpu_device *adev = knod_crypto_adev(cg);
	struct knod_crypto_req *rctx;
	struct knod_ksdma_batch sb;
	struct dma_fence *fence;
	int copies = 0, c, nents;
	struct aead_request *req;
	u32 i;

	for (i = 0; i < b->n; i++) {
		req = b->req[i];
		rctx = aead_request_ctx(req);
		rctx->out_nents = 0;
		if (!rctx->in_nents)
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
	if (!copies || knod_ksdma_begin(&sb, adev, &cg->ent[0], copies, 0))
		goto unmap;
	for (i = 0; i < b->n; i++) {
		rctx = aead_request_ctx(b->req[i]);
		if (rctx->out_nents)
			knod_crypto_copies(cg, &sb, b->req[i]->dst,
					   rctx->out_nents, rctx->slot,
					   rctx->out, true);
	}
	fence = knod_ksdma_submit(&sb);
	dma_fence_wait_timeout(fence, false, msecs_to_jiffies(1000));
	dma_fence_put(fence);
unmap:
	for (i = 0; i < b->n; i++) {
		req = b->req[i];
		rctx = aead_request_ctx(req);
		if (!rctx->out_nents)
			continue;
		dma_unmap_sg(adev->dev, req->dst, rctx->out_nents,
			     DMA_FROM_DEVICE);
		atomic64_add(rctx->out, &cg->out_bytes);
		/* For now the slot holds what went in: dst is src again. */
		if (READ_ONCE(verify) &&
		    !knod_crypto_same(req->src, req->dst, rctx->out))
			atomic64_inc(&cg->out_bad);
	}
}

/*
 * A batch's requests, for now, to the fallback, which completes them
 * through knod_crypto_sub_done(): the GPU will take them here.
 */
static void knod_crypto_run(struct knod_crypto_batch *b)
{
	struct knod_crypto_req *rctx;
	struct aead_request *sub;
	u32 i;
	int err;

	knod_crypto_in(b->cg, b);
	knod_crypto_out(b->cg, b);
	for (i = 0; i < b->n; i++) {
		rctx = aead_request_ctx(b->req[i]);
		sub = knod_crypto_subreq(b->req[i], knod_crypto_sub_done);
		err = rctx->op == KNOD_CRYPTO_OP_ENCRYPT ?
		      crypto_aead_encrypt(sub) : crypto_aead_decrypt(sub);
		if (err != -EINPROGRESS && err != -EBUSY)
			knod_crypto_finish(b->req[i], err);
	}
}

#define KNOD_CRYPTO_SPIN_NS	(20 * NSEC_PER_USEC)

/*
 * The worker, a thread a GPU: batches from the queue while there are any,
 * a short spin for more, then sleep until a request wakes it.
 */
static int knod_crypto_thread(void *data)
{
	struct knod_crypto_gpu *cg = data;
	struct knod_crypto_batch *b = cg->batch;
	u64 until;

	b->cg = cg;
	while (!kthread_should_stop()) {
		if (knod_crypto_take(cg, b)) {
			knod_crypto_run(b);
			continue;
		}
		until = ktime_get_ns() + KNOD_CRYPTO_SPIN_NS;
		while (list_empty(&cg->pending) && ktime_get_ns() < until &&
		       !kthread_should_stop())
			cpu_relax();
		set_current_state(TASK_INTERRUPTIBLE);
		if (list_empty(&cg->pending) && !kthread_should_stop())
			schedule();
		__set_current_state(TASK_RUNNING);
	}
	return 0;
}

static int knod_crypto_aead_encrypt(struct aead_request *req)
{
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct knod_crypto_req *rctx = aead_request_ctx(req);

	atomic64_inc(&ctx->cg->reqs);
	if (!knod_crypto_take_slot(req, true))
		return crypto_aead_encrypt(knod_crypto_subreq(req, NULL));
	rctx->op = KNOD_CRYPTO_OP_ENCRYPT;
	return knod_crypto_queue(req);
}

static int knod_crypto_aead_decrypt(struct aead_request *req)
{
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct knod_crypto_req *rctx = aead_request_ctx(req);

	atomic64_inc(&ctx->cg->reqs);
	if (!knod_crypto_take_slot(req, false))
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

	seq_printf(s, "tfms %lld requests %lld queued %lld fallback %lld\n",
		   atomic64_read(&cg->tfms), atomic64_read(&cg->reqs),
		   atomic64_read(&cg->queued), atomic64_read(&cg->fallback));
	seq_printf(s, "in %lld bytes, %lld requests wrong; out %lld bytes, %lld wrong (verify %s)\n",
		   atomic64_read(&cg->in_bytes), atomic64_read(&cg->in_bad),
		   atomic64_read(&cg->out_bytes), atomic64_read(&cg->out_bad),
		   READ_ONCE(verify) ? "on" : "off");
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(knod_crypto_stats);

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

/* The work buffer, its pages' SDMA addresses, and the descriptors. */
static int knod_crypto_work_init(struct knod_crypto_gpu *cg)
{
	u32 pages = KNOD_CRYPTO_SLOTS * KNOD_CRYPTO_SLOT_PAGES;
	struct knod_mem *mem;

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
		if (cg->descs)
			knod_free_mem(cg->knod, cg->descs);
		if (cg->work)
			knod_free_mem(cg->knod, cg->work);
		kvfree(cg->work_mc);
		ida_destroy(&cg->slot_ida);
		ida_destroy(&cg->key_ida);
		knod_standalone_put(cg->knod);
	}
}

static int __init knod_crypto_init(void)
{
	struct knod_crypto_gpu *cg;
	int i, err;

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
		ida_init(&cg->slot_ida);
		spin_lock_init(&cg->lock);
		INIT_LIST_HEAD(&cg->pending);

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
		if (!err) {
			cg->nent = knod_ksdma_entities_init(knod_crypto_adev(cg),
							    cg->ent,
							    KNOD_CRYPTO_RINGS);
			err = cg->nent < 0 ? cg->nent : 0;
			if (err)
				cg->nent = 0;
		}
		if (!err) {
			cg->batch = kvmalloc_obj(*cg->batch, GFP_KERNEL);
			err = cg->batch ? 0 : -ENOMEM;
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
}

module_init(knod_crypto_init);
module_exit(knod_crypto_exit);

MODULE_DESCRIPTION("KNOD: GPUs as crypto devices of their own");
MODULE_LICENSE("GPL");
