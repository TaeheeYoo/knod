/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Device memory TCP support
 *
 * Authors:	Mina Almasry <almasrymina@google.com>
 *		Willem de Bruijn <willemb@google.com>
 *		Kaiyuan Zhang <kaiyuanz@google.com>
 *
 */
#ifndef _NET_DEVMEM_H
#define _NET_DEVMEM_H

#include <linux/dma-direction.h>
#include <linux/err.h>
#include <linux/types.h>

struct device;
struct dma_buf;
struct dma_buf_attach_ops;
struct net_device;
struct net_devmem_dmabuf_binding;
struct netlink_ext_ack;

#if defined(CONFIG_NET_DEVMEM)
struct net_devmem_dmabuf_binding *
__net_devmem_binding_create(struct net_device *dev, struct device *dma_dev,
			    struct dma_buf *dmabuf,
			    enum dma_data_direction direction,
			    const struct dma_buf_attach_ops *importer_ops,
			    struct netlink_ext_ack *extack);
int net_devmem_bind_dmabuf_to_queue_direct(struct net_device *dev, u32 rxq_idx,
					   struct net_devmem_dmabuf_binding *binding);
void net_devmem_unbind_dmabuf_direct(struct net_devmem_dmabuf_binding *binding);
#else
static inline struct net_devmem_dmabuf_binding *
__net_devmem_binding_create(struct net_device *dev, struct device *dma_dev,
			    struct dma_buf *dmabuf,
			    enum dma_data_direction direction,
			    const struct dma_buf_attach_ops *importer_ops,
			    struct netlink_ext_ack *extack)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline int
net_devmem_bind_dmabuf_to_queue_direct(struct net_device *dev, u32 rxq_idx,
				       struct net_devmem_dmabuf_binding *binding)
{
	return -EOPNOTSUPP;
}

static inline void
net_devmem_unbind_dmabuf_direct(struct net_devmem_dmabuf_binding *binding)
{
}
#endif

#endif /* _NET_DEVMEM_H */
