# SPDX-License-Identifier: GPL-2.0

TEST_PROGS := \
	knod_xdp_ktime.sh \
	knod_xdp_loop.sh \
	knod_attach.sh \
# end of TEST_PROGS

TEST_FILES := \
	lib.sh \
# end of TEST_FILES

TEST_GEN_FILES += $(patsubst %.c,%.o,$(wildcard *.bpf.c))

include ../../../lib.mk

include ../../../net/bpf.mk
