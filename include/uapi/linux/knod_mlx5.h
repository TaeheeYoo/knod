/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/*
 * What of the mlx5 hardware formats the GDA shader reads and writes: the
 * completion it polls and the send WQE it posts.  Copies of the parts of
 * include/linux/mlx5/{device,qp}.h the shader touches, which the kernel
 * checks field by field against those.
 *
 * Every multi-byte field is big endian, as the hardware has it.
 */

#ifndef _UAPI_LINUX_KNOD_MLX5_H
#define _UAPI_LINUX_KNOD_MLX5_H

/* op_own: the CQE's owner bit low, its opcode in the high nibble. */
#define KNOD_MLX5_CQE_OWNER_MASK	0x01
#define KNOD_MLX5_CQE_OPCODE_SHIFT	4
#define KNOD_MLX5_CQE_REQ_ERR		0x0d
#define KNOD_MLX5_CQE_INVALID		0x0f	/* what a fresh CQ holds */

/* A CQE, and a send WQE basic block, are 1 << 6 bytes. */
#define KNOD_MLX5_CQE_SHIFT		6
#define KNOD_MLX5_WQEBB_SHIFT		6

#define KNOD_MLX5_OPCODE_SEND		0x0a
#define KNOD_MLX5_CTRL_CQ_UPDATE	0x08	/* fm_ce_se: a completion */

#ifndef __ASSEMBLY__
#include <linux/types.h>

/* struct mlx5_cqe64, down to what a completion is read for. */
struct knod_mlx5_cqe64 {
	__u8	rsvd0[12];
	__be32	rss_hash_result;
	__u8	rsvd16[28];
	__be32	byte_cnt;
	__u8	rsvd48[12];
	__be16	wqe_counter;
	__u8	signature;
	__u8	op_own;
};

/* struct mlx5_wqe_ctrl_seg */
struct knod_mlx5_wqe_ctrl_seg {
	__be32	opmod_idx_opcode;	/* wqe index << 8 | opcode */
	__be32	qpn_ds;			/* sqn << 8 | 16-byte units */
	__u8	signature;
	__u8	rsvd[2];
	__u8	fm_ce_se;
	__be32	imm;
};

/* struct mlx5_wqe_eth_seg, which the shader leaves zero. */
struct knod_mlx5_wqe_eth_seg {
	__u8	data[16];
};

/* struct mlx5_wqe_data_seg, the RQ's whole WQE and the send's last part. */
struct knod_mlx5_wqe_data_seg {
	__be32	byte_count;
	__be32	lkey;
	__be64	addr;
};

/* The send WQE the shader writes: one packet, nothing inlined. */
struct knod_mlx5_send_wqe {
	struct knod_mlx5_wqe_ctrl_seg	ctrl;
	struct knod_mlx5_wqe_eth_seg	eth;
	struct knod_mlx5_wqe_data_seg	data;
};
#endif /* !__ASSEMBLY__ */

#endif /* _UAPI_LINUX_KNOD_MLX5_H */
