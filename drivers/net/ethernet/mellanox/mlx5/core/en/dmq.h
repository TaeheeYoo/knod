/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
#ifndef __MLX5_EN_DMQ_H__
#define __MLX5_EN_DMQ_H__

#include <net/devmem_queue.h>
#include <net/netdev_queues.h>
#include "en.h"
#include "en/params.h"

/* A channel another device runs: its RQ, the XDP SQ beside it and both their
 * CQs live in that device's ring buffer, in the binding's PD.
 */
struct mlx5e_dmq_chan {
	struct net_devmem_queue *q;
	dma_addr_t *ring_dma;		/* a page each, in ring buffer order */
	u32 ring_pages;
	u32 off[NET_DMQ_MLX5_RINGS];
	u32 bytes[NET_DMQ_MLX5_RINGS];
	u32 mkey;
	u32 pdn;
	u32 uar;
	phys_addr_t uar_phys;
};

#if IS_ENABLED(CONFIG_NET_DEVMEM)
int mlx5e_dmq_query(struct net_device *dev, int idx,
		    const struct netdev_queue_config *qcfg,
		    struct net_dmq_layout *layout,
		    struct netlink_ext_ack *extack);
int mlx5e_dmq_binding_init(struct net_device *dev,
			   struct net_devmem_queue_binding *binding,
			   struct netlink_ext_ack *extack);
void mlx5e_dmq_binding_uninit(struct net_device *dev,
			      struct net_devmem_queue_binding *binding);

int mlx5e_dmq_open(struct mlx5e_channel *c, struct mlx5e_params *params,
		   struct mlx5e_channel_param *cparam, bool xsk);
void mlx5e_dmq_close(struct mlx5e_channel *c);
int mlx5e_dmq_swap(struct mlx5e_channel *c, int ring,
		   struct mlx5_wq_ctrl *wqc, struct mlx5e_dmq_saved *sv);
void mlx5e_dmq_restore(struct mlx5_wq_ctrl *wqc, struct mlx5e_dmq_saved *sv);
void mlx5e_dmq_init_cq(struct mlx5e_channel *c, int ring, struct mlx5e_cq *cq);
void mlx5e_dmq_built(struct mlx5e_channel *c);
void mlx5e_dmq_activate(struct mlx5e_channel *c);
void mlx5e_dmq_deactivate(struct mlx5e_channel *c);
void mlx5e_dmq_cq_error_dump(struct mlx5e_channel *c, struct mlx5_core_cq *mcq);
#else
static inline int mlx5e_dmq_open(struct mlx5e_channel *c,
				 struct mlx5e_params *params,
				 struct mlx5e_channel_param *cparam, bool xsk)
{
	return 0;
}

static inline void mlx5e_dmq_close(struct mlx5e_channel *c) {}

static inline int mlx5e_dmq_swap(struct mlx5e_channel *c, int ring,
				 struct mlx5_wq_ctrl *wqc,
				 struct mlx5e_dmq_saved *sv)
{
	return -EOPNOTSUPP;
}

static inline void mlx5e_dmq_restore(struct mlx5_wq_ctrl *wqc,
				     struct mlx5e_dmq_saved *sv) {}
static inline void mlx5e_dmq_init_cq(struct mlx5e_channel *c, int ring,
				     struct mlx5e_cq *cq) {}
static inline void mlx5e_dmq_built(struct mlx5e_channel *c) {}
static inline void mlx5e_dmq_activate(struct mlx5e_channel *c) {}
static inline void mlx5e_dmq_deactivate(struct mlx5e_channel *c) {}
static inline void mlx5e_dmq_cq_error_dump(struct mlx5e_channel *c,
					   struct mlx5_core_cq *mcq) {}
#endif

#endif /* __MLX5_EN_DMQ_H__ */
