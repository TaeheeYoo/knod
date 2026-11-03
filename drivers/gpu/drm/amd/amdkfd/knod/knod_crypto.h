/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR MIT */
#ifndef _UAPI_LINUX_KNOD_CRYPTO_H
#define _UAPI_LINUX_KNOD_CRYPTO_H
/*
 * knod_crypto: what the host hands KNOD_BLOB_CRYPTO_KERNEL for a batch of
 * AEAD requests, and what the kernel hands back.  The host's copy of this
 * file and knod-blob's are the same.
 *
 * A batch is a dispatch of n workgroups; workgroup i takes the request in
 * work slot slots[i]: its descriptor, its key, and its AAD, text and tag
 * at the slot's start, in that order.  It seals or opens the text in
 * place - and writes the tag after it, to seal - and its verdict to the
 * descriptor's status.
 */

#define KNOD_CRYPTO_OP_ENCRYPT		0
#define KNOD_CRYPTO_OP_DECRYPT		1

#define KNOD_CRYPTO_ST_OK		0
#define KNOD_CRYPTO_ST_BADTAG		1	/* opened: the tag was wrong */
#define KNOD_CRYPTO_ST_UNSUPPORTED	2	/* the kernel did nothing */

/* A workgroup's LDS, the host's to give each: the request's copy. */
#define KNOD_CRYPTO_LDS_BYTES		4160
/* Each lane's scratch, the host's to give: the kernel's call stack only. */
#define KNOD_CRYPTO_SCRATCH_BYTES	128

/* The kernel's code is new: each wave invalidates the instruction cache. */
#define KNOD_CRYPTO_ARGS_ICACHE_INV	1
#define KNOD_CRYPTO_ARGS_FLAGS_OFF	40

#ifndef __ASSEMBLY__
#include <linux/types.h>

/*
 * A transform's key, in its slot of a GPU's key table.  rounds 0 for
 * ChaCha20-Poly1305 (rfc7539esp: the key, then the nonce's salt), as an
 * IPsec SA has it.
 */
struct knod_crypto_key {
	__u32 key[8];
	__u32 salt;
	__u32 rounds;
	__u32 pad[6];
};

/* A request, a descriptor a work slot. */
struct knod_crypto_desc {
	__u32 key;		/* key table slot */
	__u32 op;		/* KNOD_CRYPTO_OP_* */
	__u32 assoclen;
	__u32 cryptlen;		/* the text, the tag not counted */
	__u32 authsize;
	__u32 iv[2];
	__u32 status;		/* the kernel's: KNOD_CRYPTO_ST_* */
};

/* The kernel's arguments, GPU addresses all. */
struct knod_crypto_args {
	__u64 descs;		/* struct knod_crypto_desc, a work slot each */
	__u64 keys;		/* struct knod_crypto_key, a key slot each */
	__u64 work;		/* the work slots */
	__u64 slots;		/* __u32, the batch's work slots in order */
	__u32 slot_bytes;	/* a work slot's size */
	__u32 n;		/* requests in the batch */
	__u32 flags;		/* KNOD_CRYPTO_ARGS_* */
	__u32 pad;
	__u64 times;		/* struct knod_crypto_time a workgroup, or 0 */
};

/*
 * Where a workgroup's time went, its wave's lane 0 writes: the GPU's
 * 100 MHz counter when it began, had its descriptor and key, had its
 * request in LDS, had sealed or opened it, and ended; and the unit it ran
 * on, HW_ID1: its WGP bits 13:10, shader array 16, shader engine 20:18.
 * One it left unsupported has the three between at loaded.
 */
struct knod_crypto_time {
	__u32 start;
	__u32 loaded;
	__u32 fetched;
	__u32 sealed;
	__u32 end;
	__u32 hw_id;
	__u32 pad[2];
};
#endif /* !__ASSEMBLY__ */

#endif /* _UAPI_LINUX_KNOD_CRYPTO_H */
