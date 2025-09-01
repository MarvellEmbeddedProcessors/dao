# SPDX-License-Identifier: GPL-2.0

obj-m += iliad_cdev.o

# Default to native compilation for the running kernel
KDIR ?= /lib/modules/$(shell uname -r)/build

# Cross-compilation variables (only used when explicitly set)
ifneq ($(CROSS_COMPILE),)
    # Cross-compilation mode
    ARCH ?= arm64
    KBUILD_FLAGS = ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE)
else
    # Native compilation mode
    KBUILD_FLAGS =
endif

all:
	$(MAKE) -C $(KDIR) M=$(PWD) $(KBUILD_FLAGS) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) $(KBUILD_FLAGS) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) $(KBUILD_FLAGS) modules_install

# Help target
help:
	@echo "Native compilation (default):"
	@echo "  make"
	@echo ""
	@echo "Cross-compilation examples:"
	@echo "  make CROSS_COMPILE=aarch64-marvell-linux-gnu- ARCH=arm64 KDIR=/path/to/kernel"
	@echo ""
	@echo "Variables:"
	@echo "  CROSS_COMPILE - Cross-compiler prefix (triggers cross-compilation when set)"
	@echo "  ARCH          - Target architecture (default: arm64 when cross-compiling)"
	@echo "  KDIR          - Kernel build directory (default: current running kernel)"

.PHONY: all clean install help
