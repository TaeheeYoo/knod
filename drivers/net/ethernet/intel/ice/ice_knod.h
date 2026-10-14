/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ICE_KNOD_H_
#define _ICE_KNOD_H_

struct ice_vsi;
struct ice_q_vector;
struct netdev_bpf;

int ice_knod_init(struct ice_vsi *vsi);
void ice_knod_uninit(struct ice_vsi *vsi);
int ice_knod_xdp(struct ice_vsi *vsi, struct netdev_bpf *xdp);
int ice_knod_rings(struct ice_vsi *vsi);
void ice_knod_unrings(struct ice_vsi *vsi);
u16 ice_knod_rx_buf_len(struct ice_vsi *vsi);
void ice_knod_open(struct ice_vsi *vsi);
void ice_knod_close(struct ice_vsi *vsi);
int ice_knod_drain(struct ice_q_vector *q_vector, int budget);
int ice_knod_check_channels(struct ice_vsi *vsi, int rx);
int ice_knod_check_mtu(struct ice_vsi *vsi, int mtu);

#endif /* _ICE_KNOD_H_ */
