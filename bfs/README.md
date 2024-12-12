# Marvell DAO external Buildroot package

This is external buildroot package for Marvell SoCs integrated with DAO.
It provides configuration to compile LINUX, DPDK and other DAO dependent
packages via buildroot.

## Supported SoCs

- OCTEON9
- OCTEON10

## Pre-requisites

### Host operating system

Buildroot compilation has been verified with following host OS

- Ubuntu-22.04

### Install Packages

Following packages are required for buildroot compilation as a pre-requisite:

```sh

$ apt install sed build-essential git cpio python3 unzip rsync bc wget texinfo \
  > automake libtool pkg-config flex bison uuid-dev lib32stdc++6 lib32z1 \
  > acpica-tools dosfstools libconfig-dev libmbedtls-dev libnuma-dev \
  > liblzma-dev libarchive-zip-perl python3-pycryptodome python3-pyelftools \
  > libfdt-dev libncurses-dev libpci-dev libyaml-dev \
  > python3 python3-sphinx python3-sphinx-rtd-theme libssl-dev \
  > linux-modules-extra-$(uname -r)

```

### Download toolchain

Buildroot compilation has been verified with following compiler

- Marvell Aarch64 Cross compiler (GCC-13)
  (https://github.com/MarvellEmbeddedProcessors/Octeon-Toolchain)

```sh

$ cd <build_dir>
$ wget https://github.com/MarvellEmbeddedProcessors/Octeon-Toolchain/raw/refs/heads/master/marvell-tools-13004.0.tar.bz2
$ tar -xvf marvell-tools-13004.0.tar.bz2

```

### Create link to toolchain

```sh

$ cd <build_dir>
$ ln -sf ./marvell-tools-13004.0 toolchain

```

### Clone buildroot repository

```sh

$ cd <build_dir>
$ git clone --branch 2024.11.1 --depth 1 https://github.com/buildroot/buildroot.git

```

### Clone DAO repository

```sh

$ cd <build_dir>
$ git clone --branch <release-tag> --depth 1 https://github.com/MarvellEmbeddedProcessors/dao.git

```

### Apply buildroot patches

```sh

$ cd <build_dir>/buildroot
$ git am -3 ../dao/patches/buildroot/2024.11.1/*.patch

```

## Build buildroot

### Create default configuration file

```sh

$ cd <build_dir>/buildroot
$ BR2_EXTERNAL=<build_dir>/dao/bfs make octeon_cn9k_defconfig

```

### Create configuration for specific board use case (ex: Liquid Crypto)

```sh

$ cat ../dao/bfs/configs/octeon_cn9k_defconfig ../dao/bfs/board/octeon_cn9k/lc/octeon_cn9k_defconfig_extra > ../dao/bfs/configs/octeon_cn9k_lc_defconfig
$ cd <build_dir>/buildroot
$ BR2_EXTERNAL=<build_dir>/dao/bfs make octeon_cn9k_lc_defconfig

```

### Update configuration (Optional step)
If needed update buildroot's and LINUX's default configuration using:

```sh

$ cd <build_dir>/buildroot
$ BR2_EXTERNAL=<build_dir>/dao/bfs make menuconfig
$ BR2_EXTERNAL=<build_dir>dao/bfs make linux-menuconfig

```

### Compile buildroot (full build)

```sh

$ cd <build_dir>/buildroot
$ BR2_EXTERNAL=<build_dir>/dao/bfs make V=1

```

### Compile single package (instead of full build)

```sh

$ cd <buildroot path>
$ BR2_EXTERNAL=<DAO_PATH>/bfs make marvell-dpdk-[build | re-build | install | clean ]
$ BR2_EXTERNAL=<DAO_PATH>/bfs make linux-[build | re-build | install | clean ]
$ BR2_EXTERNAL=<DAO_PATH>/bfs make grpc-[build | re-build | install | clean ]
$ BR2_EXTERNAL=<DAO_PATH>/bfs make dao-[build | re-build | install | clean ]

```
