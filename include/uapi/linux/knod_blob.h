/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/*
 * Contract between the knod BPF JIT and the prebuilt map routines it loads.
 *
 * The routines are AMDGCN machine code, assembled per ISA outside the kernel
 * and shipped as one file per ISA under /lib/firmware/knod.  The JIT picks one
 * by (kind, key size) and copies its bytes into the program it is building, so
 * a routine runs in the same wave as the surrounding code and shares its
 * register file.  What follows is what keeps the two from colliding.
 *
 * Anything here is a binary interface: change it and every existing blob stops
 * working, so bump KNOD_BLOB_ABI_VERSION when you do.  The kernel refuses a
 * blob whose version it does not recognise.
 */

#ifndef _UAPI_LINUX_KNOD_BLOB_H
#define _UAPI_LINUX_KNOD_BLOB_H

#include <linux/types.h>

#define KNOD_BLOB_MAGIC		0x4b4e4442	/* 'KNDB' */
#define KNOD_BLOB_ABI_VERSION	10

/*
 * How a routine is reached.  SPLICE is what the JIT does: the bytes are copied
 * into the caller's instruction stream and the routine ends by falling through
 * into whatever comes next.  CALL is reserved for reaching a single shared
 * copy through s_swappc_b64, which would let routines be compiled from C
 * rather than written in assembly, at the cost of the JIT having to spill
 * around a calling convention.  Only the register binding differs.
 *
 * Macros rather than an enum because the assembly selects on these, and a name
 * the preprocessor cannot see is not an error to it - it is zero, which is a
 * value one of these has.
 */
#define KNOD_BLOB_LINK_SPLICE	0
#define KNOD_BLOB_LINK_CALL	1

#ifndef __ASSEMBLY__

/*
 * Which routine an entry holds.  Array maps index straight into storage, so
 * the key length never changes their code and one entry covers every map of
 * that type.  Hash maps compare the key and carry one entry per key length.
 * The prologue and the epilogue take no key, so one entry covers each.
 */
enum knod_blob_kind {
	KNOD_BLOB_LOOKUP_ARRAY = 0,
	KNOD_BLOB_UPDATE_ARRAY,
	KNOD_BLOB_DELETE_ARRAY,
	KNOD_BLOB_LOOKUP_PERCPU_ARRAY,
	KNOD_BLOB_UPDATE_PERCPU_ARRAY,
	KNOD_BLOB_DELETE_PERCPU_ARRAY,
	KNOD_BLOB_LOOKUP_HASH,
	KNOD_BLOB_UPDATE_HASH,
	KNOD_BLOB_DELETE_HASH,
	/* Not spliced into a program but wrapped around it.  The epilogue is
	 * in two pieces because the JIT puts the packet-cache writeback
	 * between them, and how long that is follows the program.
	 */
	KNOD_BLOB_PROLOGUE,
	KNOD_BLOB_EPILOGUE_PRE,
	KNOD_BLOB_EPILOGUE_POST,
	/* Not spliced into anything: the whole of what the core dispatches
	 * before a feature has claimed the slot.  It ends the wave and pads to
	 * where the prefetcher may reach, and that is all it does.
	 */
	KNOD_BLOB_DEFAULT_KERNEL,
	/* Also whole rather than spliced: prologue, a fixed XDP_PASS, epilogue.
	 * What the BPF feature runs with no program attached.
	 */
	KNOD_BLOB_PASS_KERNEL,
	/* The inbound ESP pipeline, whole: parse, SA lookup, AES-CTR decrypt,
	 * GHASH, ICV verify, verdict.  Not spliced into anything either.
	 */
	KNOD_BLOB_IPSEC_FUSED,
	/* Stages of that pipeline on their own, for measuring what each costs.
	 * key_chunks says which, matching enum knod_ipsec_bench_kernel.
	 */
	KNOD_BLOB_IPSEC_BENCH,
	KNOD_BLOB_KIND_MAX,
};

#endif /* !__ASSEMBLY__ */

/* Hash keys are stored padded to four bytes and compared a dword at a time,
 * so a hash routine exists per DIV_ROUND_UP(key_size, 4).  Both sides zero
 * the padding, so the last dword compares equal without masking.
 *
 * The ceiling is not a round number because it is not a choice: a lookup
 * holds the key and the stored key it is comparing against at the same time,
 * and twice fourteen dwords is what the scratch window has room for.  This is
 * the same limit the JIT enforces as MAX_MAP_KEY_SIZE.
 */
#define KNOD_BLOB_KEY_CHUNKS_MAX	14

/*
 * Where a hash element keeps its key and its value, both padded to eight
 * bytes: RDNA3 faults on a misaligned atomic and a program may update a value
 * with one.  Here rather than in the descriptor because a routine is
 * assembled against these as immediate offsets.  "RDNA3" ISA 3.3.3:
 * https://docs.amd.com/v/u/en-US/rdna3-shader-instruction-set-architecture-feb-2023_0
 */
#define KNOD_BLOB_ELEM_KV_OFF		8
#define KNOD_BLOB_ELEM_VALUE_OFF(key_chunks)				\
	(KNOD_BLOB_ELEM_KV_OFF + (((key_chunks) * 4 + 7) & ~7))

/*
 * Register binding, splice linkage.
 *
 * The JIT keeps BPF r0-r10 in v0-v21 and everything a routine touches lives
 * above that.  Nothing below v22 may be read or written, with one exception
 * below.
 *
 * The scratch window is scoped to one routine and to nothing else.  It holds
 * no meaning before a routine starts or after it ends, each routine uses it
 * however it likes, and two routines spliced one after the other share
 * nothing through it.  So the JIT must not keep a value there across a splice,
 * and a routine that wants to hand something back puts it in the result
 * register rather than leaving it in scratch.
 *
 * The map descriptor address is uniform - the JIT knows it at compile time -
 * so it arrives in an SGPR pair, and every other address a routine needs is a
 * scalar load away from it.  Nothing in a blob has to be relocated.
 */
#define KNOD_BLOB_SPLICE_DESC_SREG	32	/* s[32:33] map descriptor */
/* The window stops below what the prologue leaves for the epilogue, the first
 * of which is the lane's slot at v[58:59].
 */
#define KNOD_BLOB_SPLICE_TMP_VREG	22	/* v22-v57 clobberable */
#define KNOD_BLOB_SPLICE_TMP_VREG_END	57

/*
 * The exception.  A routine that stands in for a BPF helper returns where the
 * BPF calling convention says a helper returns, which is r0 - so it writes
 * v[0:1] and the JIT moves nothing afterwards.  That is not the JIT's register
 * allocation leaking into a blob: which pair holds r0 is published right above,
 * and r0 is the one BPF register a helper is defined to write.
 *
 * A routine that is not a helper has no such convention to borrow and puts its
 * result here instead.  None exists yet; the binding is written down so the
 * first one does not have to invent it.
 */
#define KNOD_BLOB_SPLICE_R0_VREG	0	/* v[0:1] helper return */
#define KNOD_BLOB_SPLICE_RET_VREG	26	/* v[26:27] otherwise */

/*
 * The key, and for an update the value, arrive in registers rather than
 * through a pointer: the JIT keeps the BPF stack in VGPRs, so neither has an
 * address until one is made for it, and a routine wants them in registers
 * anyway - it would only have loaded them back.
 *
 * They sit at fixed places in the scratch window, so the front of that window
 * is an input where the rest of it means nothing on entry.  A routine may
 * destroy either once it is done reading it.
 *
 * That is what bounds a value the same way it bounds a key.  A hash update
 * holds the search key and the value at once and compares the stored key a
 * chunk at a time between them, which is slower than holding that whole too -
 * and is why lookup, which is the hot one, still holds it whole.
 */
#define KNOD_BLOB_SPLICE_KEY_VREG	28	/* v28-v41 */
#define KNOD_BLOB_SPLICE_VAL_VREG	42	/* v42-v55 */
#define KNOD_BLOB_VALUE_CHUNKS_MAX	14

/*
 * Register binding, call linkage.  Matches the AMDGPU function ABI so that a
 * routine can be compiled: arguments in the low registers, return address in
 * s[32:33].
 */
#define KNOD_BLOB_CALL_DESC_SREG	0	/* s[0:1] */
#define KNOD_BLOB_CALL_KEY_VREG		0	/* v[0:1] */
#define KNOD_BLOB_CALL_VAL_VREG		2	/* v[2:3] */
#define KNOD_BLOB_CALL_RET_VREG		0	/* v[0:1] */
#define KNOD_BLOB_CALL_RET_ADDR_SREG	32	/* s[32:33] */

/*
 * Where a routine saves EXEC, and the scalars it may destroy while running.
 * The register numbers are baked into the assembly, so unlike the pairs the JIT
 * hands out for BPF-level scopes these cannot be assigned at compile time - the
 * JIT keeps the whole range free instead, and an entry says through
 * exec_save_pairs how much of the first part a routine uses.
 *
 * Nothing below this is scratch.  In particular s[36:37] carries the mask of
 * lanes that have reached a verdict, which is live from wherever a lane
 * finished to the epilogue that reads it, and so across any splice.
 */
#define KNOD_BLOB_EXEC_SAVE_SREG	38	/* s[38:39] .. s[48:49] */
#define KNOD_BLOB_EXEC_SAVE_PAIRS_MAX	6
#define KNOD_BLOB_SPLICE_TMP_SREG	50	/* s50-s53 clobberable */
#define KNOD_BLOB_SPLICE_TMP_SREG_END	53

/*
 * The JIT's own scalars, at the same numbers on every generation so that a
 * routine names them without asking which GPU it was built for.
 */
#define KNOD_BLOB_DONE_MASK_SREG	36
/* What a probe build holds across the program: what the prologue took, and
 * when it ended.  s[34:35] is the pair nothing else claims - GFX9 corrupts it,
 * which costs nothing because GFX9 has no cycle counter to read either.
 */
#define KNOD_BLOB_PROBE_SREG		34

#define KNOD_BLOB_INITIAL_EXEC_SREG	100

/*
 * Where the IPsec shader reads an inbound ESP packet, for a plain IPv4 frame
 * with no VLAN and no options, and what it writes back.  The host builds the
 * packets the KAT and the benchmark feed it, so both sides have to agree; one
 * definition rather than one on each side of the firmware boundary.
 */
#define KNOD_BLOB_ESP_SPI_OFF		34	/* ETH(14) + IPv4(20) */
#define KNOD_BLOB_ESP_SEQ_OFF		38
#define KNOD_BLOB_ESP_IV_OFF		42
#define KNOD_BLOB_ESP_CTEXT_OFF		50	/* SPI(4) + seq(4) + IV(8) */
#define KNOD_BLOB_ESP_ICV_LEN		16

/* Verdicts, in the high half of bd->act.  Below these is the SA slot the
 * packet matched, so they count down from the top.
 */
#define KNOD_BLOB_VERDICT_SA_MISS	0xFFFFFFFFu
#define KNOD_BLOB_VERDICT_BYPASS	0xFFFFFFFEu
#define KNOD_BLOB_VERDICT_ICV_FAIL	0xFFFFFFFDu

/*
 * EXEC contract, both linkages.
 *
 * A routine inherits whatever mask the caller had and must leave it exactly as
 * it found it.  Narrowing is relative - s_and_saveexec_b64 against the
 * inherited mask - so lanes the caller had already disabled stay disabled, and
 * a routine must not assume every lane is live.  In particular it elects lanes
 * with mbcnt over the current EXEC rather than testing for lane zero, which
 * would do nothing if lane zero came in disabled.
 *
 * Entry with EXEC == 0 is the caller's problem: scalar instructions are not
 * masked, so the JIT guards a splice with s_cbranch_execz.
 */

/*
 * What a routine is given about the map, in GPU memory.
 *
 * This exists so a blob never has to know the layout of the kernel's own map
 * object, which carries fields no routine reads and a union whose shape
 * depends on the map type.  The kernel fills one of these per map and hands
 * its address to the routine; the kernel side stays free to change.
 *
 * Addresses are GPU virtual.  Fields that do not apply to a map type are
 * zero - an array map has no buckets, a hash map has no per-instance stride.
 */
#ifndef __ASSEMBLY__

struct knod_blob_map_desc {
	__u32	key_size;
	__u32	value_size;
	__u32	max_entries;
	__u32	elem_size;		/* hash: header + padded key + value */
	__u64	bucket_gaddr;		/* hash: bucket heads */
	__u64	elems_gaddr;		/* value storage, either kind */
	__u64	queue_gaddr;		/* hash: free-element queue */
	__u64	gc_list_gaddr;		/* hash: deferred free list */
	__u64	gc_count_gaddr;		/* hash: deferred free count */
	__u64	per_instance_size;	/* percpu array: stride per instance */
	__u32	n_buckets;		/* hash */
	__u32	lock_offset;		/* hash: from bucket_gaddr to the locks */
	__u32	hashrnd;		/* hash */
	__u32	reserved;
	/* Index of the next element to hand out of queue_gaddr, counting down.
	 * An insert takes one with an atomic decrement, so a routine needs the
	 * address rather than the value.  On the end, where adding it moves no
	 * offset a routine was already assembled against.
	 */
	__u64	free_cur_gaddr;		/* hash */
};

#endif /* !__ASSEMBLY__ */

/* Offsets a routine loads the above with.  Assembly includes this header
 * too, so these have to be macros rather than offsetof().
 */
#define KNOD_BLOB_DESC_KEY_SIZE		0
#define KNOD_BLOB_DESC_VALUE_SIZE	4
#define KNOD_BLOB_DESC_MAX_ENTRIES	8
#define KNOD_BLOB_DESC_ELEM_SIZE	12
#define KNOD_BLOB_DESC_BUCKET		16
#define KNOD_BLOB_DESC_ELEMS		24
#define KNOD_BLOB_DESC_QUEUE		32
#define KNOD_BLOB_DESC_GC_LIST		40
#define KNOD_BLOB_DESC_GC_COUNT		48
#define KNOD_BLOB_DESC_PER_INSTANCE	56
#define KNOD_BLOB_DESC_N_BUCKETS	64
#define KNOD_BLOB_DESC_LOCK_OFFSET	68
#define KNOD_BLOB_DESC_HASHRND		72
#define KNOD_BLOB_DESC_FREE_CUR		80
#define KNOD_BLOB_DESC_SIZE		88

/*
 * What the prologue walks to reach a lane's packet, in the order it does it.
 *
 * The dispatch packet gives it the parameter block; the parameter block gives
 * it this workgroup's ring descriptor and this lane's context; the ring
 * descriptor gives it a buffer descriptor; the buffer descriptor gives it the
 * page and the offset within it.  None of that is the routine's to choose, so
 * unlike the map descriptor these are the kernel's own structures, published
 * so a prologue built outside the kernel can read them.
 *
 * Anything here changing is an ABI break, same as the register binding.
 */
#define KNOD_BLOB_AQL_KERNARG		40	/* hsa_kernel_dispatch_packet */

#define KNOD_BLOB_PARAM_NR_BACKLOGS	0
#define KNOD_BLOB_PARAM_NR_QUEUES	4
#define KNOD_BLOB_PARAM_SPSC_STRIDE	8
/* Shift counts, in the two pairs a scalar load reaches them in. */
#define KNOD_BLOB_PARAM_BATCH_SHIFT	16
#define KNOD_BLOB_PARAM_WG_SHIFT	20
#define KNOD_BLOB_PARAM_PAGE_SHIFT	24
#define KNOD_BLOB_PARAM_SPSC_SHIFT	28
#define KNOD_BLOB_PARAM_KTIME_NS	32
#define KNOD_BLOB_PARAM_PASS_COUNT	40
#define KNOD_BLOB_PARAM_PASS_META	168
#define KNOD_BLOB_PARAM_QUEUES		424
#define KNOD_BLOB_PARAM_PASS_INDICES	1448
#define KNOD_BLOB_PARAM_SUB		132520

/* knod_bpf_queue_desc, one per ring.  count through ring_mask land in one
 * four-dword load, which is why the padding is there.
 */
#define KNOD_BLOB_QUEUE_POOL_GADDR	0
#define KNOD_BLOB_QUEUE_BASE_GADDR	8
#define KNOD_BLOB_QUEUE_COUNT		16
#define KNOD_BLOB_QUEUE_RING_START	24
#define KNOD_BLOB_QUEUE_RING_MASK	28
#define KNOD_BLOB_QUEUE_SIZE		32

/* spsc_bd.  off and len share a dword, low half first. */
#define KNOD_BLOB_BD_ACT		8
#define KNOD_BLOB_BD_OFF		16
#define KNOD_BLOB_BD_PAGE_IDX		20

/* knod_bpf_subparam_obj, one per lane: the xdp_md the program is handed. */
#define KNOD_BLOB_SUB_DATA		0
#define KNOD_BLOB_SUB_DATA_END		8
#define KNOD_BLOB_SUB_DATA_META		16
#define KNOD_BLOB_SUB_INGRESS_IFINDEX	24
#define KNOD_BLOB_SUB_RX_QUEUE_INDEX	32
#define KNOD_BLOB_SUB_EGRESS_IFINDEX	40
#define KNOD_BLOB_SUB_RETVAL		48
#define KNOD_BLOB_SUB_SIZE		56

/* spsc_bd fills half of the 64-byte slot it sits in.  A probe build puts its
 * three counts - prologue, program, epilogue - in the half nothing reads, so
 * carrying them costs no layout and no version.
 *
 * Counts and not stamps: the counter one is read from is per compute unit, so
 * two waves that ran on different ones have no common origin and the earliest
 * start across a dispatch cannot be told.  Stamping the end was tried, and the
 * spread it reported was the counter's own range.  What is comparable is a
 * difference taken inside one wave, which is what these are.
 */
#define KNOD_BLOB_BD_PROBE		32

/* The BPF stack the frame pointer starts at the top of. */
#define KNOD_BLOB_BPF_STACK_SIZE	512

/*
 * Register binding for the prologue and the epilogue.
 *
 * These two are not spliced into the middle of a program the way a map routine
 * is; they are its ends.  So they have no arguments - the prologue reads what
 * the hardware and the dispatch packet give it, and leaves the program its
 * context, packet bounds and slot address in registers the epilogue reads back.
 * That set is the whole of the contract.
 */
#define KNOD_BLOB_PRO_DISPATCH_SREG	4	/* s[4:5] dispatch packet */
#define KNOD_BLOB_PRO_WG_X_SREG		14
#define KNOD_BLOB_PRO_WG_Y_SREG		15	/* also the queue id */
#define KNOD_BLOB_PRO_PARAM_SREG	30	/* s[30:31] parameter block */
#define KNOD_BLOB_PRO_FRAME_SREG	32
#define KNOD_BLOB_PRO_TID_VREG		0	/* v0, from the hardware */

/* What the prologue leaves behind. */
#define KNOD_BLOB_PRO_SLOT_VREG		58	/* v[58:59] the lane's spsc_bd */
#define KNOD_BLOB_PRO_CTX_VREG		60	/* v[60:61] the lane's xdp_md */
#define KNOD_BLOB_PRO_IDX_VREG		62	/* backlog index, flat */
#define KNOD_BLOB_PRO_DATA_VREG		64	/* v[64:65] packet start */
#define KNOD_BLOB_PRO_DATA_END_VREG	66	/* v[66:67] packet end */
#define KNOD_BLOB_PRO_PAGE_BASE_VREG	68	/* v[68:69] before the offset */
/* The page the producer named, carried across the program so the epilogue can
 * write it back unchanged.  It only does that to put the verdict, the bounds
 * and this in one store instead of two: what a dispatch costs follows how many
 * stores a lane makes, because they are what keeps dispatches from
 * overlapping.  So a prologue that does not leave it here and an epilogue that
 * writes it are not interchangeable, which is what the version above is for.
 */
#define KNOD_BLOB_PRO_PAGE_IDX_VREG	63

/* Scratch it may use while doing so, which is the same window a map routine
 * gets, plus the scalars nothing holds across a dispatch.
 */
#define KNOD_BLOB_PRO_TMP_VREG		22	/* v22-v57 */
#define KNOD_BLOB_PRO_TMP_SREG		18	/* s18-s29 */

#ifndef __ASSEMBLY__

struct knod_blob_hdr {
	__le32	magic;			/* KNOD_BLOB_MAGIC */
	__le32	abi_version;		/* KNOD_BLOB_ABI_VERSION */
	__le32	isa;			/* 9, 10 or 11 */
	__le32	link_mode;		/* enum knod_blob_link */
	__le32	wave_size;		/* 32 or 64 */
	__le32	n_entries;
	__le32	entry_offset;		/* to knod_blob_entry[n_entries] */
	__le32	reserved;
};

struct knod_blob_entry {
	__le32	kind;			/* enum knod_blob_kind */
	__le32	key_chunks;		/* DIV_ROUND_UP(key_size, 4); 0 = any */
	__le32	code_offset;		/* from the start of the file */
	__le32	code_size;		/* bytes, a multiple of 4 */
	__le32	exec_save_pairs;	/* of KNOD_BLOB_EXEC_SAVE_SREG */
	__le32	reserved;
};

#endif /* !__ASSEMBLY__ */

#endif /* _UAPI_LINUX_KNOD_BLOB_H */
