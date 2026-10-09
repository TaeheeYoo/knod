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

#define KNOD_BLOB_MAGIC		0x4b4e4442	/* 'KNDB' */
#define KNOD_BLOB_ABI_VERSION	34

/*
 * How an entry is used: the kernel puts the engine at the shader's entry with
 * the program after it, and a program calls the rest.  The container's field
 * for it has one value, which keeps its old name.
 */
#define KNOD_BLOB_LINK_SPLICE	0

#ifndef __ASSEMBLY__

#include <linux/types.h>

/*
 * Which routine an entry holds.  Array maps index straight into storage, so
 * the key length never changes their code and one entry covers every map of
 * that type.  Hash maps compare the key and carry one entry per key length.
 * Nor do a program's ends or the engine, so one entry covers each.
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
	/* Per-cpu hash: one element per key, but n_instances value slots; the
	 * routine adds workgroup_id_y * per_instance_size to reach this
	 * instance's slot.  Delete is element-level (same as plain hash).
	 */
	KNOD_BLOB_LOOKUP_PERCPU_HASH,
	KNOD_BLOB_UPDATE_PERCPU_HASH,
	KNOD_BLOB_DELETE_PERCPU_HASH,
	/* The program that runs when none is attached: the two GDA ends
	 * around a fixed XDP_PASS.
	 */
	KNOD_BLOB_GDA_RX_KERNEL,
	/* What runs the NIC's rings and calls the program once a round.  It
	 * goes at the kernel's entry with the program right after it, and its
	 * call_patch is where its offset to the program goes.
	 */
	KNOD_BLOB_GDA_ENGINE,
	/* bpf_xdp_adjust_head() and bpf_xdp_adjust_tail(), called. */
	KNOD_BLOB_XDP_ADJUST_HEAD,
	KNOD_BLOB_XDP_ADJUST_TAIL,
	/* BPF_DIV and BPF_MOD, unsigned and signed, of 32 and 64 bits.
	 * Dividend in v[0:1], divisor in v[2:3], result back in v[0:1].
	 */
	KNOD_BLOB_DIV32,
	KNOD_BLOB_DIV64,
	KNOD_BLOB_MOD32,
	KNOD_BLOB_MOD64,
	KNOD_BLOB_SDIV32,
	KNOD_BLOB_SDIV64,
	KNOD_BLOB_SMOD32,
	KNOD_BLOB_SMOD64,
	/* KNOD_BLOB_GDA_ENGINE for a program whose packets have to see each
	 * other's map writes.  Every lane runs the program once; a lane the
	 * program parks (KNOD_BLOB_RANK_PARKED) is run again, from where the
	 * program resumes it, once the packets before it of its flow - the
	 * NIC's RSS hash - have run, one rank of the flow at a time.  It
	 * wants KNOD_PERSIST_GDA_ORDER_LDS_BYTES.  In the BPF container, as
	 * only a program can want it.
	 */
	KNOD_BLOB_GDA_ENGINE_ORDERED,
	/* Called by such a program where it decides which lanes go on: every
	 * lane of the wave, v0 the LDS offset the waves meet at, v1 the wave,
	 * v2 the lane's rank flags.  Returns, per lane, nonzero to park it:
	 * one that took part (KNOD_BLOB_RANK_REACHED or _ACTIVE) and is not
	 * the first of its flow to, where some lane of the flow is
	 * KNOD_BLOB_RANK_ACTIVE.  Every wave calls it once, in the first pass.
	 */
	KNOD_BLOB_GDA_GATE,
	KNOD_BLOB_KIND_MAX,
};

#endif /* !__ASSEMBLY__ */

/* Hash keys are stored padded to four bytes and compared a dword at a time,
 * so a hash routine exists per DIV_ROUND_UP(key_size, 4).  Both sides zero
 * the padding, so the last dword compares equal without masking.
 *
 * The ceiling is MAX_MAP_KEY_SIZE, the JIT's: an update's key and value both
 * arrive as arguments, and with the descriptor fourteen dwords of each is
 * what the calling convention passes in registers.
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

/*
 * An element's link, and a bucket head: the next element's index, or where
 * the chain ends KNOD_BLOB_HASH_NULLS with the bucket's index, so that a
 * lookup that ended on another bucket's chain - its element was reused for
 * a key there while it walked - knows to start again, as the kernel's
 * hlist_nulls does.  An element not on any chain links to
 * KNOD_BLOB_HASH_NULLS_FREE, no bucket's.  KNOD_BLOB_HASH_DELETED marks one
 * just unlinked, for a walker already on it.
 */
#define KNOD_BLOB_HASH_DELETED		0x80000000u
#define KNOD_BLOB_HASH_NULLS		0x40000000u
#define KNOD_BLOB_HASH_LINK_MASK	0x7fffffffu
#define KNOD_BLOB_HASH_NULLS_FREE	0x7fffffffu
#define KNOD_BLOB_ELEM_VALUE_OFF(key_chunks)				\
	(KNOD_BLOB_ELEM_KV_OFF + (((key_chunks) * 4 + 7) & ~7))

/*
 * The word between an element's link and its key: KNOD_BLOB_ELEM_LIVE and its
 * bucket from KNOD_BLOB_ELEM_BUCKET_SHIFT up while the element is on a chain,
 * and for an LRU map KNOD_BLOB_ELEM_REF once a lookup or an overwrite has used
 * it since eviction last passed.
 */
#define KNOD_BLOB_ELEM_LRU_OFF		4
#define KNOD_BLOB_ELEM_LIVE		0x1
#define KNOD_BLOB_ELEM_REF		0x2
#define KNOD_BLOB_ELEM_BUCKET_SHIFT	2

/*
 * Register binding.
 *
 * The VGPRs split in two at KNOD_BLOB_JIT_VREG.  Below it is everything code
 * compiled from C may destroy - its arguments, its result, its temporaries -
 * and nothing lives across a call there.  From it up is what the JIT and the
 * engine hold across a program: the BPF registers, rN in the pair from
 * KNOD_BLOB_BPF_VREG(N), lo then hi, what the engine leaves the program, and
 * the engine's state.  Nothing compiled may touch those, and the build
 * refuses a function that would.
 */
#define KNOD_BLOB_JIT_VREG		64
#define KNOD_BLOB_BPF_VREG(r)		(KNOD_BLOB_JIT_VREG + 2 * (r))

/*
 * A map routine is a function the JIT calls, compiled from C to the AMDGPU
 * calling convention: s_swappc_b64 s[30:31] in, s_setpc_b64 s[30:31] out.
 * The JIT places each one it calls once, after the program.  So are the
 * helper routines, whose arguments and results are their own; below is a
 * map routine's.
 *
 * - v[0:1] is the map descriptor's address, then the key's dwords from v2,
 *   then for an update KNOD_BLOB_VALUE_CHUNKS_MAX of the value's and its
 *   flags.  The result comes back in v[0:1], and the JIT moves it to r0.
 * - s13 is the queue, which a percpu map's instance is.
 * - s32 is the stack, each lane's scratch from KNOD_BLOB_CALL_STACK_OFF,
 *   past the BPF stack's place there; KNOD_BLOB_CALL_STACK_BYTES of it.
 * - The callee may destroy any VGPR below KNOD_BLOB_JIT_VREG and any SGPR
 *   below s34, VCC included.  The JIT keeps nothing there across a call.  It
 *   keeps s34 and up itself, as the convention has it, and the build refuses
 *   a function that touches a VGPR from KNOD_BLOB_JIT_VREG up.
 * - EXEC is whatever lanes the call is for, and it comes back the same.  The
 *   JIT does not call with none.
 */
#define KNOD_BLOB_VALUE_CHUNKS_MAX	14
/* An update's flags, after its value: BPF_ANY, BPF_NOEXIST or BPF_EXIST. */
#define KNOD_BLOB_UPDATE_FLAGS_VREG(key_chunks)				\
	(2 + (key_chunks) + KNOD_BLOB_VALUE_CHUNKS_MAX)
#define KNOD_BLOB_CALL_STACK_OFF	528
#define KNOD_BLOB_CALL_STACK_BYTES	64

/*
 * The scalars a program holds, all where a call keeps them: the mask of lanes
 * that have reached a verdict, live from wherever a lane finished to the
 * program's exit; and the lanes the program started with.
 */
#define KNOD_BLOB_DONE_MASK_SREG	34	/* s[34:35] */
#define KNOD_BLOB_INITIAL_EXEC_SREG	96	/* s[96:97] */

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
	__u32	flags;			/* KNOD_BLOB_MAP_* */
	/* Index of the next element to hand out of queue_gaddr, counting down.
	 * An insert takes one with an atomic decrement, so a routine needs the
	 * address rather than the value.  On the end, where adding it moves no
	 * offset a routine was already assembled against.
	 */
	__u64	free_cur_gaddr;		/* hash */
	/* An LRU hash's eviction hand: the next element to look at, counting
	 * up past max_entries, which is a power of two.
	 */
	__u64	clock_gaddr;		/* LRU hash */
	__u32	n_instances;		/* percpu: value copies */
	__u32	reserved;
};

/* A hash that evicts rather than refuses an insert when it is full. */
#define KNOD_BLOB_MAP_LRU	0x1

#endif /* !__ASSEMBLY__ */



/*
 * The parameter block a program runs against: the page size, the clock, per
 * queue the bounds a program's packet may reach, and per lane the xdp_md the
 * program is handed.  The kernel's own structure, published so the engine,
 * built outside the kernel, can find a lane's context in it.
 *
 * Anything here changing is an ABI break, same as the register binding.
 */
#define KNOD_BLOB_PARAM_PAGE_SHIFT	0
#define KNOD_BLOB_PARAM_KTIME_NS	8
#define KNOD_BLOB_PARAM_QUEUES		16
#define KNOD_BLOB_PARAM_SUB		272

/* knod_bpf_queue_desc, one per queue.  rx_bounds is the frame a packet may
 * grow into: the headroom before its data in the low 16 bits and the frame's
 * size in the high, or zero for none.
 */
#define KNOD_BLOB_QUEUE_RX_BOUNDS	0
#define KNOD_BLOB_QUEUE_SIZE		8

/* knod_bpf_subparam_obj, one per lane: the xdp_md the program is handed. */
#define KNOD_BLOB_SUB_DATA		0
#define KNOD_BLOB_SUB_DATA_END		8
#define KNOD_BLOB_SUB_DATA_META		16
#define KNOD_BLOB_SUB_INGRESS_IFINDEX	24
#define KNOD_BLOB_SUB_RX_QUEUE_INDEX	32
#define KNOD_BLOB_SUB_EGRESS_IFINDEX	40
#define KNOD_BLOB_SUB_RETVAL		48
#define KNOD_BLOB_SUB_SIZE		56

/* The BPF stack the frame pointer starts at the top of. */
#define KNOD_BLOB_BPF_STACK_SIZE	512

/*
 * What the GDA engine leaves a program, which is what the program's code was
 * translated to find.  The engine calls it with s_swappc_b64 s[98:99] and gets
 * its verdicts back in r0; the program leaves s98-s103 and the engine's state
 * alone, and s32 the stack the engine pointed it at.
 */
/* Scratch, for a BPF stack too deep for LDS and for the calls into C.  gfx10
 * hands the wave the ring's descriptor and its own offset into it, and the
 * engine's first act is to build FLAT_SCRATCH from them; gfx11 arrives with
 * FLAT_SCRATCH set.
 */
#define KNOD_BLOB_PRO_SCRATCH_DESC_SREG	0	/* s[0:3] */
#define KNOD_BLOB_PRO_SCRATCH_WAVE_SREG	14	/* gfx10 only */
#define KNOD_BLOB_PRO_PARAM_SREG	36	/* s[36:37] parameter block */
/* Where the program returns to, and what the engine keeps across it, past
 * anything the JIT allocates.
 */
#define KNOD_BLOB_PRO_RET_SREG		98	/* s[98:99] */
#define KNOD_BLOB_ENGINE_SREG		100	/* s100-s103 */
#define KNOD_BLOB_PRO_QUEUE_SREG	102
/* Past the BPF registers. */
#define KNOD_BLOB_PRO_OFF_VREG		86	/* the packet's offset in its page */
#define KNOD_BLOB_PRO_IDX_VREG		87	/* the lane in all queues */
#define KNOD_BLOB_PRO_CTX_VREG		88	/* v[88:89] the lane's xdp_md */
#define KNOD_BLOB_PRO_DATA_VREG		90	/* v[90:91] packet start */
#define KNOD_BLOB_PRO_DATA_END_VREG	92	/* v[92:93] packet end */
#define KNOD_BLOB_PRO_PAGE_BASE_VREG	94	/* v[94:95] the page */
#define KNOD_BLOB_PRO_PAGE_IDX_VREG	96	/* its index in the RX buffer */
/* The lane in the queue, where the JIT finds the lane's LDS stack by.  It is
 * read before the program's first instruction, so it need not last.
 */
#define KNOD_BLOB_PRO_LOCAL_IDX_VREG	40
/* The engine's state across a program, past the JIT's LDS temporaries: the
 * ring state and the packet count, and the ordered engine's packet ranks.
 */
#define KNOD_BLOB_PRO_GDA_VREG		100
#define KNOD_BLOB_PRO_GDA_VREGS		4
/* The ordered engine's: KNOD_BLOB_RANK_NONE for a lane without a packet; for
 * a parked one, once the first pass is over, its rank among its flow's
 * packets in the round; with the flags the program and the engine pass
 * between them above it.  And the pass, zero the first.
 */
#define KNOD_BLOB_PRO_RANK_VREG		(KNOD_BLOB_PRO_GDA_VREG + 3)
#define KNOD_BLOB_PRO_PASS_SREG		104
#define KNOD_BLOB_RANK_MASK		0xffff
#define KNOD_BLOB_RANK_NONE		0xffff
#define KNOD_BLOB_RANK_PARKED		0x10000	/* run again */
#define KNOD_BLOB_RANK_REACHED		0x20000	/* read what the order is for */
#define KNOD_BLOB_RANK_ACTIVE		0x40000	/* about to write it */

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
	__le32	exec_save_pairs;	/* zero */
	/* The engine's: where in it the 32-bit offset of its call to the
	 * program goes, program - (engine + call_patch - 4).  callee_offset
	 * and callee_size are zero; all three are for every other entry.
	 */
	__le32	call_patch;
	__le32	callee_offset;		/* from the start of the file */
	__le32	callee_size;
};

#endif /* !__ASSEMBLY__ */

#endif /* _UAPI_LINUX_KNOD_BLOB_H */
