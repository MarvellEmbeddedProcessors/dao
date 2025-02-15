# Marvell DAO external Buildroot package

This is external buildroot package for Marvell SoCs integrated with DAO.
It provides configuration to compile LINUX, DPDK and other DAO dependent
packages via buildroot.

## How to build

```sh

ln -sf <CROSS_COMPILE_TOOLCHAIN_PATH> <DAO_PATH>/../toolchain
git clone --branch 2024.11.1 --depth 1 https://github.com/buildroot/buildroot.git
cd ./buildroot
git am -3 <DAO_PATH>/patches/buildroot/2024.11.1/*.patch
BR2_EXTERNAL=<DAO_PATH>/bfs make octeon_cn9k_defconfig
BR2_EXTERNAL=<DAO_PATH>/bfs make V=1

```

## Menuconfig

```sh

cd <buildroot path>
BR2_EXTERNAL=<DAO_PATH>/bfs make octeon_cn9k_defconfig
BR2_EXTERNAL=<DAO_PATH>/bfs make menuconfig
BR2_EXTERNAL=<DAO_PATH>/bfs make linux-menuconfig

```
## Package specific commands

```sh

cd <buildroot path>
BR2_EXTERNAL=<DAO_PATH>/bfs make marvell-dpdk-[build | re-build | install | clean ]
BR2_EXTERNAL=<DAO_PATH>/bfs make linux-[build | re-build | install | clean ]
BR2_EXTERNAL=<DAO_PATH>/bfs make grpc-[build | re-build | install | clean ]
BR2_EXTERNAL=<DAO_PATH>/bfs make dao-[build | re-build | install | clean ]

```
