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

struct knod_crypto_gpu {
	struct knod *knod;
	struct dentry *dir;
};

static struct knod_crypto_gpu knod_crypto_gpus[KNOD_CRYPTO_MAX_GPUS];
static int knod_crypto_nr;

static struct amdgpu_device *knod_crypto_adev(struct knod_crypto_gpu *cg)
{
	return cg->knod->process->pdds[0]->dev->adev;
}

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

static void knod_crypto_put_all(void)
{
	struct knod_crypto_gpu *cg;

	while (knod_crypto_nr) {
		cg = &knod_crypto_gpus[--knod_crypto_nr];
		debugfs_remove_recursive(cg->dir);
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
		/* dri/<N>/knod/crypto/, beside what the context put there. */
		cg->dir = debugfs_create_dir("crypto", cg->knod->debug_dir);
		debugfs_create_file("aperture", 0400, cg->dir, cg,
				    &knod_crypto_aperture_fops);
		debugfs_create_file("sdma_bench", 0400, cg->dir, cg,
				    &knod_crypto_sdma_bench_fops);
		knod_crypto_nr++;
		pr_info("knod_crypto: GPU %d, %d queues\n", gpus[i], queues);
	}
	return 0;
}

static void __exit knod_crypto_exit(void)
{
	knod_crypto_put_all();
}

module_init(knod_crypto_init);
module_exit(knod_crypto_exit);

MODULE_DESCRIPTION("KNOD: GPUs as crypto devices of their own");
MODULE_LICENSE("GPL");
