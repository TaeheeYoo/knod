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
#include <crypto/chacha.h>
#include <crypto/internal/aead.h>
#include "kfd_priv.h"
#include "kfd_knod.h"

#define KNOD_CRYPTO_MAX_GPUS	16

static int gpus[KNOD_CRYPTO_MAX_GPUS] = { 128 };
static int nr_gpus = 1;
module_param_array(gpus, int, &nr_gpus, 0444);
MODULE_PARM_DESC(gpus, "The GPUs, by render node: 128 for /dev/dri/renderD128 (default 128)");

static int queues = 2;
module_param(queues, int, 0444);
MODULE_PARM_DESC(queues, "AQL queues to dispatch on, each GPU");

/*
 * A transform's key as the GPU reads it, in its slot of the GPU's key
 * table: ChaCha20's eight words and the nonce's salt, rounds 0 as an IPsec
 * SA has it for ChaCha20-Poly1305.
 */
#define KNOD_CRYPTO_KEY_SLOTS	4096

struct knod_crypto_key {
	u32 key[8];
	u32 salt;
	u32 rounds;
	u32 pad[6];
};

/*
 * A request's place on its GPU while it is there: a slot of the work buffer
 * in VRAM for its AAD, text and tag, and its descriptor in GTT, which the
 * shader reads and writes its verdict to and the host reads back.
 */
#define KNOD_CRYPTO_SLOT	SZ_64K
#define KNOD_CRYPTO_SLOTS	2048		/* 128 MB of VRAM */
#define KNOD_CRYPTO_SLOT_PAGES	(KNOD_CRYPTO_SLOT >> PAGE_SHIFT)

#define KNOD_CRYPTO_OP_ENCRYPT	0
#define KNOD_CRYPTO_OP_DECRYPT	1
#define KNOD_CRYPTO_ST_BADTAG	1

struct knod_crypto_desc {
	u32 key;		/* key table slot */
	u32 op;			/* KNOD_CRYPTO_OP_* */
	u32 assoclen;
	u32 cryptlen;		/* the text, the tag not counted */
	u32 authsize;
	u32 iv[2];
	u32 status;		/* the shader's: 0 or KNOD_CRYPTO_ST_* */
};

/* Requests that go to the GPU together, a workgroup each. */
#define KNOD_CRYPTO_BATCH	256

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
	int slot;		/* in the work buffer, -1 for none */
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

/* The request to the fallback, which completes it as the caller asked. */
static struct aead_request *knod_crypto_subreq(struct aead_request *req)
{
	struct knod_crypto_tfm *ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct knod_crypto_req *rctx = aead_request_ctx(req);
	struct aead_request *sub = &rctx->sub;

	atomic64_inc(&ctx->cg->reqs);
	atomic64_inc(&ctx->cg->fallback);
	aead_request_set_tfm(sub, ctx->fallback);
	aead_request_set_callback(sub, req->base.flags, req->base.complete,
				  req->base.data);
	aead_request_set_crypt(sub, req->src, req->dst, req->cryptlen,
			       req->iv);
	aead_request_set_ad(sub, req->assoclen);
	return sub;
}

static int knod_crypto_aead_encrypt(struct aead_request *req)
{
	return crypto_aead_encrypt(knod_crypto_subreq(req));
}

static int knod_crypto_aead_decrypt(struct aead_request *req)
{
	return crypto_aead_decrypt(knod_crypto_subreq(req));
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

	seq_printf(s, "tfms %lld requests %lld fallback %lld\n",
		   atomic64_read(&cg->tfms), atomic64_read(&cg->reqs),
		   atomic64_read(&cg->fallback));
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
		if (err) {
			knod_crypto_nr++;
			knod_crypto_put_all();
			return err;
		}
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
