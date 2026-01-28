# SPDX-License-Identifier: GPL-2.0
ccflags-y := $(MODULE_CFLAGS)
obj-m   := octep-rdma.o
octep-rdma-y := octep_rdma.o octep_sdp.o octep_sdp_custom.o octep_sdp_regs.o octep_verbs.o octep_mbox.o \
		 octep_qp.o octep_mr.o octep_ah.o octep_cq.o octep_pd.o octep_pfvf_mbox.o
KDIR    := /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)

all:
	$(MAKE) -j $(FLAGS) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
