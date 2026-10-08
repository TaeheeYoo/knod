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
#define KNOD_BLOB_ABI_VERSION	25

/*
 * How a routine is reached, the only way there is: the JIT copies its bytes
 * into the program, and it ends by falling through into whatever comes next.
 * What it calls, it calls through its entry's callee.
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
	/* The mailbox batch path's, no longer built or loaded. */
	KNOD_BLOB_PROLOGUE,
	KNOD_BLOB_EPILOGUE,
	/* Not spliced into anything: the whole of what the core dispatches
	 * before a feature has claimed the slot.  It ends the wave and pads to
	 * where the prefetcher may reach, and that is all it does.
	 */
	KNOD_BLOB_DEFAULT_KERNEL,
	/* The mailbox batch path's, no longer built or loaded. */
	KNOD_BLOB_PASS_KERNEL,
	KNOD_BLOB_RESERVED_IPSEC_FUSED,
	KNOD_BLOB_RESERVED_IPSEC_BENCH,
	/* The program that runs when none is attached: the two GDA ends
	 * around a fixed XDP_PASS.
	 */
	KNOD_BLOB_GDA_RX_KERNEL,
	/* A program's two ends, spliced around it: its frame on the way in;
	 * on the way out the lanes that did not return dropped, its stores
	 * waited for, and back to the engine.
	 */
	KNOD_BLOB_GDA_PROLOGUE,
	KNOD_BLOB_GDA_EPILOGUE,
	/* What runs the NIC's rings and calls the program once a round.  It
	 * goes at the kernel's entry with the program right after it, and its
	 * call_patch is where its offset to the program goes.
	 */
	KNOD_BLOB_GDA_ENGINE,
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
 * Splice linkage.
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
#define KNOD_BLOB_SPLICE_DESC_SREG	28	/* s[28:29] map descriptor */
#define KNOD_BLOB_SPLICE_TMP_VREG	22	/* v22-v57 clobberable */
#define KNOD_BLOB_SPLICE_TMP_VREG_END	57

/*
 * The exception.  A routine stands in for a BPF helper, and returns where the
 * BPF calling convention says a helper returns, which is r0 - so it writes
 * KNOD_BLOB_BPF_VREG(0) and the JIT moves nothing afterwards.  r0 is the one
 * BPF register a helper is defined to write.
 */
#define KNOD_BLOB_SPLICE_R0_VREG	KNOD_BLOB_BPF_VREG(0)

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
 * Where a routine saves EXEC, and the scalars it may destroy while running.
 * The register numbers are baked into the assembly, so unlike the pairs the JIT
 * hands out for BPF-level scopes these cannot be assigned at compile time - the
 * JIT keeps the whole range free instead, and an entry says through
 * exec_save_pairs how much of the first part a routine uses.
 *
 * Nothing below this is scratch.  In particular s[32:33] carries the mask of
 * lanes that have reached a verdict, which is live from wherever a lane
 * finished to the program's exit that reads it, and so across any splice.
 */
#define KNOD_BLOB_EXEC_SAVE_SREG	34	/* s[34:35] .. s[44:45] */
#define KNOD_BLOB_EXEC_SAVE_PAIRS_MAX	6
#define KNOD_BLOB_SPLICE_TMP_SREG	46	/* s46-s49 clobberable */
#define KNOD_BLOB_SPLICE_TMP_SREG_END	49

/*
 * A routine may call code compiled from C, its entry's callee.  The call follows
 * the AMDGPU calling convention, which lets the callee destroy registers the
 * JIT keeps state in and gives it a stack, so the routine has to bring both:
 *
 * - The stack is each lane's scratch from KNOD_BLOB_CALL_STACK_OFF, past the
 *   BPF stack's place there, KNOD_BLOB_CALL_STACK_BYTES of it.  The routine
 *   points s32 at it for the call.
 * - What the callee destroys and the JIT still needs, the routine keeps and
 *   puts back: scalars in s34-s49, then lanes of KNOD_BLOB_CALL_SAVE_VREG,
 *   which holds nothing across a routine.  No VGPR: the callee keeps below
 *   KNOD_BLOB_JIT_VREG, where nothing is live across it.
 *
 * The kernel sizes scratch and declares VGPRs to cover both.
 */
#define KNOD_BLOB_CALL_STACK_OFF	528
#define KNOD_BLOB_CALL_STACK_BYTES	64
#define KNOD_BLOB_CALL_SAVE_VREG	104
#define KNOD_BLOB_CALL_SAVE_VREGS	1

/*
 * The JIT's own scalars, at the same numbers on every generation so that a
 * routine names them without asking which GPU it was built for.
 */
#define KNOD_BLOB_DONE_MASK_SREG	32
#define KNOD_BLOB_INITIAL_EXEC_SREG	96

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
 * translated to find.  The engine calls it with s_swappc_b64 s[6:7] and gets
 * its verdicts back in r0; the program leaves s0, s2, s[6:11] and the engine's
 * state alone.
 */
/* Scratch, for a BPF stack too deep for LDS and for the calls into C.  gfx10
 * hands the wave the ring's descriptor and its own offset into it, and the
 * engine's first act is to build FLAT_SCRATCH from them; gfx11 arrives with
 * FLAT_SCRATCH set.
 */
#define KNOD_BLOB_PRO_SCRATCH_DESC_SREG	0	/* s[0:3] */
#define KNOD_BLOB_PRO_SCRATCH_WAVE_SREG	14	/* gfx10 only */
#define KNOD_BLOB_PRO_WG_Y_SREG		13	/* the queue */
#define KNOD_BLOB_PRO_PARAM_SREG	26	/* s[26:27] parameter block */
#define KNOD_BLOB_PRO_FRAME_SREG	28
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
/* The engine's state across a program, past the JIT's LDS temporaries. */
#define KNOD_BLOB_PRO_GDA_VREG		100
#define KNOD_BLOB_PRO_GDA_VREGS		3

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
	/* A routine that calls code placed elsewhere: where in the routine
	 * the call's 32-bit offset goes, callee - (routine + call_patch - 4),
	 * and the callee if the blob holds it.  The JIT puts a callee once
	 * after the program, however many places splice routines calling it;
	 * the engine's callee is the program.  All zero for a routine that
	 * calls nothing.
	 */
	__le32	call_patch;
	__le32	callee_offset;		/* from the start of the file */
	__le32	callee_size;
};

#endif /* !__ASSEMBLY__ */

#endif /* _UAPI_LINUX_KNOD_BLOB_H */
