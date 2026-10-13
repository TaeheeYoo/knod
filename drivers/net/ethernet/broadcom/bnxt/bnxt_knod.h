/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BNXT_KNOD_H
#define BNXT_KNOD_H

struct bnxt;
struct bnxt_napi;
struct netdev_bpf;
struct cpumask;

int bnxt_knod_init(struct bnxt *bp);
void bnxt_knod_uninit(struct bnxt *bp);
int bnxt_knod_xdp(struct bnxt *bp, struct netdev_bpf *xdp);
int bnxt_knod_rings(struct bnxt *bp);
void bnxt_knod_unrings(struct bnxt *bp);
void bnxt_knod_irq_moved(struct bnxt *bp, int i, const struct cpumask *mask);
void bnxt_knod_open(struct bnxt *bp);
void bnxt_knod_close(struct bnxt *bp);
int bnxt_knod_drain(struct bnxt *bp, struct bnxt_napi *bnapi, int budget);
int bnxt_knod_check_channels(struct bnxt *bp, int rx);

#endif
