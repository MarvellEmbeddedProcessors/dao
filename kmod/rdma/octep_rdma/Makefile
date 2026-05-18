# SPDX-License-Identifier: GPL-2.0
ccflags-y := $(MODULE_CFLAGS)
obj-m   := octep-rdma.o

# Common source files (used in both x86 EP and Octeon termination modes)
octep-rdma-y := octep_rdma.o octep_rdma_netdev.o octep_verbs.o octep_mbox.o \
		 octep_qp.o octep_mr.o octep_ah.o octep_cq.o octep_pd.o

ifneq ($(findstring -DCONFIG_OCTEP_RDMA_OCTTERM,$(MODULE_CFLAGS)),)
# Octeon termination mode: add cdev, exclude x86-only PCI EP files
octep-rdma-y += octterm_cdev.o
else
# x86 EP mode: include PCI EP device, register setup, and PF-VF mbox files
octep-rdma-y += octep_ep.o octep_ep_regs.o octep_pfvf_mbox.o
endif

KDIR    := /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)

all:
	$(MAKE) -j $(FLAGS) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
