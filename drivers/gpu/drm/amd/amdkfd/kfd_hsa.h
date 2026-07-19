/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef KFD_HSA_CODE_H_
#define KFD_HSA_CODE_H_

struct amd_queue_properties {
	u32 enable_trap_handler:1,
	    is_ptr64:1,
	    enable_trap_handler_debug_sgprs:1,
	    enable_profiling:1,
	    use_scratch_once:1,
	    reserved1:27;
};

enum hsa_packet_type {
	/*
	 * Vendor-specific packet.
	 */
	HSA_PACKET_TYPE_VENDOR_SPECIFIC = 0,
	/*
	 * The packet has been processed in the past, but has not been reassigned to
	 * the packet processor. A packet processor must not process a packet of this
	 * type. All queues support this packet type.
	 */
	HSA_PACKET_TYPE_INVALID = 1,
	/*
	 * Packet used by agents for dispatching jobs to kernel agents. Not all
	 * queues support packets of this type (see ::hsa_queue_feature_t).
	 */
	HSA_PACKET_TYPE_KERNEL_DISPATCH = 2,
	/*
	 * Packet used by agents to delay processing of subsequent packets, and to
	 * express complex dependencies between multiple packets. All queues support
	 * this packet type.
	 */
	HSA_PACKET_TYPE_BARRIER_AND = 3,
	/*
	 * Packet used by agents for dispatching jobs to agents.  Not all
	 * queues support packets of this type (see ::hsa_queue_feature_t).
	 */
	HSA_PACKET_TYPE_AGENT_DISPATCH = 4,
	/*
	 * Packet used by agents to delay processing of subsequent packets, and to
	 * express complex dependencies between multiple packets. All queues support
	 * this packet type.
	 */
	HSA_PACKET_TYPE_BARRIER_OR = 5
};

enum hsa_packet_header {
	/*
	 * Packet type. The value of this sub-field must be one of
	 * ::hsa_packet_type_t. If the type is ::HSA_PACKET_TYPE_VENDOR_SPECIFIC, the
	 * packet layout is vendor-specific.
	 */
	HSA_PACKET_HEADER_TYPE = 0,
	/*
	 * Barrier bit. If the barrier bit is set, the processing of the current
	 * packet only launches when all preceding packets (within the same queue) are
	 * complete.
	 */
	HSA_PACKET_HEADER_BARRIER = 8,
	/*
	 * Acquire fence scope. The value of this sub-field determines the scope and
	 * type of the memory fence operation applied before the packet enters the
	 * active phase. An acquire fence ensures that any subsequent global segment
	 * or image loads by any unit of execution that belongs to a dispatch that has
	 * not yet entered the active phase on any queue of the same kernel agent,
	 * sees any data previously released at the scopes specified by the acquire
	 * fence. The value of this sub-field must be one of ::hsa_fence_scope_t.
	 */
	HSA_PACKET_HEADER_ACQUIRE_FENCE_SCOPE = 9,
	/*
	 * Release fence scope, The value of this sub-field determines the scope and
	 * type of the memory fence operation applied after kernel completion but
	 * before the packet is completed. A release fence makes any global segment or
	 * image data that was stored by any unit of execution that belonged to a
	 * dispatch that has completed the active phase on any queue of the same
	 * kernel agent visible in all the scopes specified by the release fence. The
	 * value of this sub-field must be one of ::hsa_fence_scope_t.
	 */
	HSA_PACKET_HEADER_RELEASE_FENCE_SCOPE = 11
};

struct code_properties {
	    /* 4-sgprs */
	u16 enable_sgpr_private_segment_buffer:1,
	    /* 2-sgprs */
	    enable_sgpr_dispatch_ptr:1,
	    /* 2-sgprs */
	    enable_sgpr_queue_ptr:1,
	    /* 2-sgprs */
	    enable_sgpr_kernarg_segment_ptr:1,
	    /* 2-sgprs */
	    enable_sgpr_dispatch_id:1,
	    /* 2-sgprs */
	    enable_sgpr_flat_scratch_init:1,
	    /* 2-sgprs */
	    enable_sgpr_private_segment_size:1,
	    reserved0:3,
	    enable_wavefront_size32:1, // gfx10+
	    uses_dynamic_stack:1,
	    reserved1:4;
};

struct compute_pgm_rsrc1 {
	u32 granulated_workitem_vgpr_count:6,
	    granulated_wavefront_sgpr_count:4,
	    priority:2,
	    float_round_mode_32:2,
	    float_round_mode_16_64:2,
	    float_denorm_mode_32:2,
	    float_denorm_mode_16_64:2,
	    priv:1,
	    enable_dx10_clamp:1,
	    debug_mode:1,
	    enable_ieee_mode:1,
	    bulky:1,
	    cdbg_user:1,
	    fp16_ovfl:1,	/* gfx9+ */
	    reserved0:2,
	    wgp_mode:1,		/* gfx10+ */
	    mem_ordered:1,	/* gfx10+ */
	    fwd_progress:1;	/* gfx10+ */
};

struct compute_pgm_rsrc2 {
	    /* 1-sgprs
	     * enable_sgpr_private_segment_wavefront_offset
	     */
	u32 enable_private_segment:1,
	    /* More or equal to enable_sgpr_*.
	     * Exceed 16 will be ignored.
	     */
	    user_sgpr_count:5,
	    enable_trap_handler:1,
	    /* 1-sgpr */
	    enable_sgpr_workgroup_id_x:1,
	    /* 1-sgpr */
	    enable_sgpr_workgroup_id_y:1,
	    /* 1-sgpr */
	    enable_sgpr_workgroup_id_z:1,
	    /* 1-sgpr */
	    enable_sgpr_workgroup_info:1,
	    enable_vgpr_workitem_id:2,
	    enable_exception_address_watch:1,
	    enable_exception_memory:1,
	    granulated_lds_size:9,
	    enable_exception_ieee_754_fp_invalid_operation:1,
	    enable_exception_fp_denormal_source:1,
	    enable_exception_ieee_754_fp_division_by_zero:1,
	    enable_exception_ieee_754_fp_overflow:1,
	    enable_exception_ieee_754_fp_underflow:1,
	    enable_exception_ieee_754_fp_inexact:1,
	    enable_exception_int_divide_by_zero:1,
	    reserved0:1;
};

struct compute_pgm_rsrc3 {
	u32 accum_offset:6,
	    reserved0:10,
	    tg_split:1,
	    reserved1:15;
};

struct kernel_descriptor {
	u32 group_segment_fixed_size;
	u32 private_segment_fixed_size;
	u32 kernarg_size;
	u8 reserved0[4];
	s64 kernel_code_entry_byte_offset;
	u8 reserved1[20];
	struct compute_pgm_rsrc3 compute_pgm_rsrc3; /* GFX10+ and GFX90A+ */
	struct compute_pgm_rsrc1 compute_pgm_rsrc1;
	struct compute_pgm_rsrc2 compute_pgm_rsrc2;
	struct code_properties code_properties;
	u8 reserved2[6];
};

enum hsa_queue_type {
	HSA_QUEUE_TYPE_MULTI = 0,
	HSA_QUEUE_TYPE_SINGLE = 1
};

enum hsa_queue_feature {
	HSA_QUEUE_FEATURE_KERNEL_DISPATCH = 1,
	HSA_QUEUE_FEATURE_AGENT_DISPATCH = 2
};

struct hsa_kernel_dispatch_packet {
	u16 header;
	u16 setup;
	u16 workgroup_size_x;
	u16 workgroup_size_y;
	u16 workgroup_size_z;
	u16 reserved0;
	u32 grid_size_x;
	u32 grid_size_y;
	u32 grid_size_z;
	u32 private_segment_size;
	u32 group_segment_size;
	u64 kernel_object;
	void *kernarg_address;
	u64 reserved2;
	u64 completion_signal;
};

enum amd_signal_kind {
	AMD_SIGNAL_KIND_INVALID = 0,
	AMD_SIGNAL_KIND_USER = 1,
	AMD_SIGNAL_KIND_DOORBELL = -1,
	AMD_SIGNAL_KIND_LEGACY_DOORBELL = -2
};

/* An AMD Signal object must always be 64 byte aligned to ensure it cannot
 * span a page boundary. This is required by CP microcode which optimizes
 * access to the structure by only doing a single SUA (System Uniform Address)
 * translation when accessing signal fields. This optimization is used in GFX8.
 */
struct amd_signal {
	u64 kind;
	union {
		volatile s64 value;
		volatile u32 *legacy_hardware_doorbell_ptr;
		volatile u64 *hardware_doorbell_ptr;
	};
	/* For AMD_SIGNAL_KIND_USER: mailbox address for event notification
	 * in Signal operations.
	 */
	u64 event_mailbox_ptr;
	/* For AMD_SIGNAL_KIND_USER: event id for event notification in Signal
	 * operations.
	 */
	u32 event_id;
	u32 reserved1;
	/* Start of the AQL packet timestamp, when profiled. */
	u64 start_ts;
	/* End of the AQL packet timestamp, when profiled. */
	u64 end_ts;
	union {
		/* For AMD_SIGNAL_KIND_*DOORBELL: the address of the associated
		 * amd_queue, otherwise reserved and must be 0.
		 */
		void *queue_ptr;
		u64 reserved2;
	};
	u32 reserved3[2];
} __aligned(64);

struct hsa_queue {
	u32 type;

	u32 features;

	void *base_address;
	/*
	 * Signal object used by the application to indicate the ID of a packet that
	 * is ready to be processed. The HSA runtime manages the doorbell signal. If
	 * the application tries to replace or destroy this signal, the behavior is
	 * undefined.
	 *
	 * If @a type is ::HSA_QUEUE_TYPE_SINGLE, the doorbell signal value must be
	 * updated in a monotonically increasing fashion. If @a type is
	 * ::HSA_QUEUE_TYPE_MULTI, the doorbell signal value can be updated with any
	 * value.
	 */
	u64 doorbell_signal;

	/*
	 * Maximum number of packets the queue can hold. Must be a power of 2.
	 */
	u32 size;
	/* Reserved. Must be 0. */
	u32 reserved1;
	/*
	 * Queue identifier, which is unique over the lifetime of the application.
	 */
	u64 id;

};

enum hsa_fence_scope {
	HSA_FENCE_SCOPE_NONE = 0,
	HSA_FENCE_SCOPE_AGENT = 1,
	HSA_FENCE_SCOPE_SYSTEM = 2
};

struct amd_queue {
	struct hsa_queue hsa_queue;
	u32 reserved1[4];
	volatile u64 write_dispatch_id;
	u32 group_segment_aperture_base_hi;
	u32 private_segment_aperture_base_hi;
	u32 max_cu_id;
	u32 max_wave_id;
	volatile u64 max_legacy_doorbell_dispatch_id_plus_1;
	volatile u32 legacy_doorbell_lock;
	u32 reserved2[9];
	volatile u64 read_dispatch_id;
	u32 read_dispatch_id_field_base_byte_offset;
	u32 compute_tmpring_size;
	u32 scratch_resource_descriptor[4];
	u64 scratch_backing_memory_location;
	u64 scratch_backing_memory_byte_size;
	u32 scratch_wave64_lane_byte_size;
	struct amd_queue_properties queue_properties;
	u32 reserved3[2];
	u64 queue_inactive_signal;
	u32 reserved4[14];
} __aligned(64);

struct hsa_sync_var {
	union {
		/* pointer to user mode data */
		void *user_data;
		/* 64bit compatibility of value */
		u64 user_data_ptr_value;
	};
	u64 SyncVarSize;
};

enum hsa_event_type {
	/* user-mode generated GPU signal */
	HSA_EVENTTYPE_SIGNAL		= 0,
	/* HSA node change (attach/detach) */
	HSA_EVENTTYPE_NODECHANGE	= 1,
	/* HSA device state change( start/stop ) */
	HSA_EVENTTYPE_DEVICESTATECHANGE = 2,
	/* GPU shader exception event   */
	HSA_EVENTTYPE_HW_EXCEPTION	= 3,
	/* GPU SYSCALL with parameter info */
	HSA_EVENTTYPE_SYSTEM_EVENT	= 4,
	/* GPU signal for debugging     */
	HSA_EVENTTYPE_DEBUG_EVENT	= 5,
	/* GPU signal for profiling     */
	HSA_EVENTTYPE_PROFILE_EVENT	= 6,
	/* GPU signal queue idle state (EOP pm4) */
	HSA_EVENTTYPE_QUEUE_EVENT	= 7,
	/* GPU signal for signaling memory access faults and memory subsystem issues */
	HSA_EVENTTYPE_MEMORY		= 8,
	/* ... */
	HSA_EVENTTYPE_MAXID,
	HSA_EVENTTYPE_TYPE_SIZE		= 0xffffffff
};

enum hsa_eventtype_nodechange_flags {
	HSA_EVENTTYPE_NODECHANGE_ADD	= 0,
	HSA_EVENTTYPE_NODECHANGE_REMOVE	= 1,
	HSA_EVENTTYPE_NODECHANGE_SIZE	= 0xffffffff
};

struct hsa_node_change {
	/* HSA node added/removed on the platform */
	enum hsa_eventtype_nodechange_flags flags;
};

enum hsa_device {
	HSA_DEVICE_CPU	= 0,
	HSA_DEVICE_GPU	= 1,
	MAX_HSA_DEVICE	= 2
};

enum hsa_eventtype_devicestatechange_flags {
	/* device started (and available) */
	HSA_EVENTTYPE_DEVICESTATUSCHANGE_START	= 0,
	/* device stopped (i.e. unavailable) */
	HSA_EVENTTYPE_DEVICESTATUSCHANGE_STOP	= 1,
	HSA_EVENTTYPE_DEVICESTATUSCHANGE_SIZE	= 0xffffffff
};

struct hsa_device_state_change {
	/* F-NUMA node that contains the device */
	u32 node_id;
	/* device type: GPU or CPU */
	enum hsa_device device;
	/* event flags */
	enum hsa_eventtype_devicestatechange_flags flags;
};

struct hsa_access_attribute_failure {
	/* Page not present or supervisor privilege */
	unsigned int not_present:1;
	/* Write access to a read-only page */
	unsigned int readonly:1;
	/* Execute access to a page marked NX */
	unsigned int no_execute:1;
	/* Host access only */
	unsigned int gpu_access:1;
	/* RAS ECC failure (notification of DRAM ECC - non-recoverable -
	 * error, if supported by HW)
	 */
	unsigned int ecc:1;
	/* Can't determine the exact fault address */
	unsigned int imprecise:1;
	/* Indicates RAS errors or other errors causing the access to GPU to fail
	 * 0 = no RAS error,
	 * 1 = ECC_SRAM,
	 * 2 = Link_SYNFLOOD (poison),
	 * 3 = GPU hang (not attributable to a specific cause), other values reserved
	 */
	unsigned int error_type:3;
	/* must be 0 */
	unsigned int Reserved:23;
};

enum hsa_eventid_memory_flags {
	/* access fault, recoverable after page adjustment */
	HSA_EVENTID_MEMORY_RECOVERABLE		= 0,
	/* memory access requires process context destruction, unrecoverable */
	HSA_EVENTID_MEMORY_FATAL_PROCESS	= 1,
	/* memory access requires all GPU VA context destruction, unrecoverable */
	HSA_EVENTID_MEMORY_FATAL_VM		= 2,
};

struct hsa_memory_access_fault {
	/* H-NUMA node that contains the device where the memory access occurred */
	u32 node_id;
	/* virtual address this occurred on */
	u64 virtual_address;
	/* failure attribute */
	struct hsa_access_attribute_failure failure;
	/* event flags */
	enum hsa_eventid_memory_flags flags;
};

struct hsa_event_data {
	enum hsa_event_type event_type;

	union {
		/* return data associated with HSA_EVENTTYPE_SIGNAL and other events */
		struct hsa_sync_var sync_var;
		/* data associated with HSA_EVENTTYPE_NODE_CHANGE */
		struct hsa_node_change node_change_state;
		/* data associated with HSA_EVENTTYPE_DEVICE_STATE_CHANGE */
		struct hsa_device_state_change    device_state;
		/* data associated with HSA_EVENTTYPE_MEMORY */
		struct hsa_memory_access_fault    memory_access_fault;
	};

	// the following data entries are internal to the KFD & thunk itself.

	u64 hw_data1; // internal thunk store for Event data  (OsEventHandle)
	u64 hw_data2; // internal thunk store for Event data  (HWAddress)
	u32 hw_data3; // internal thunk store for Event data  (HWData)
};

struct hsa_event {
	u32 event_id;
	struct hsa_event_data event_data;
};

#endif /* KFD_HSA_CODE_H_ */
