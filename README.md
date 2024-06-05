# DPU Accelerator Offload(DAO)

DPU Accelerator Offload(DAO) provides library interfaces which enable developers
to implement their own application on top of Marvell's OCTEON based data
processing units.
It also comes with applications aimed at supporting accelerated switching and
packet processing.

| Repository             | Ubuntu-22.04                                                                                                                                  | Status                                                                                                                                                                                                                        |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **_marvell-dao_**      | ![GitHub Release](https://img.shields.io/github/v/release/MarvellEmbeddedProcessors/dpu-accelerator-offload?sort=semver&display_name=release) | [![build](https://github.com/MarvellEmbeddedProcessors/dpu-accelerator-offload/actions/workflows/build.yml/badge.svg)](https://github.com/MarvellEmbeddedProcessors/dpu-accelerator-offload/actions/workflows/build.yml)      |
| **_marvell-dpdk_**     | ![GitHub Release](https://img.shields.io/github/v/release/MarvellEmbeddedProcessors/marvell-dpdk?sort=semver&display_name=release)            | [![dependency](https://github.com/MarvellEmbeddedProcessors/marvell-dpdk-test/actions/workflows/build-cn10k.yml/badge.svg)](https://github.com/MarvellEmbeddedProcessors/marvell-dpdk-test/actions/workflows/build-cn10k.yml) |
| **_marvell-ovs_**      | ![GitHub Release](https://img.shields.io/github/v/release/MarvellEmbeddedProcessors/marvell-ovs?sort=semver&display_name=release)             | [![build-cn10k](https://github.com/MarvellEmbeddedProcessors/marvell-ovs/actions/workflows/build-cn10k.yml/badge.svg)](https://github.com/MarvellEmbeddedProcessors/marvell-ovs/actions/workflows/build-cn10k.yml)            |
| **_marvell-vpp_**      | ![GitHub Release](https://img.shields.io/github/v/release/MarvellEmbeddedProcessors/vpp?sort=semver&display_name=release)                     | [![build-cn10k](https://github.com/MarvellEmbeddedProcessors/vpp/actions/workflows/build.yml/badge.svg?branch=stable%2F2402)](https://github.com/MarvellEmbeddedProcessors/vpp/actions/workflows/build.yml)                   |
| **_marvell-packages_** |                                                                                                                                               | [![Commit and deploy package](https://github.com/MarvellEmbeddedProcessors/packages/actions/workflows/push-package.yml/badge.svg)](https://github.com/MarvellEmbeddedProcessors/packages/actions/workflows/push-package.yml)  |

## Programmers Guide

https://marvellembeddedprocessors.github.io/dpu-accelerator-offload/guides/

## API Reference Guide

https://marvellembeddedprocessors.github.io/dpu-accelerator-offload/api/

## Quick start Guide

Update ubuntu repository to download dao packages

```sh

curl -fsSL https://uat.marvell.com/public/repo/octeon/dao/ubuntu/dao.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/dao.gpg
curl -SsL -o /etc/apt/sources.list.d/dao.list https://uat.marvell.com/public/repo/octeon/dao/ubuntu/dao.list
sudo chmod 644 /etc/apt/sources.list.d/dao.list
sudo chmod 644 /etc/apt/keyrings/dao.gpg
apt-get update

```

Installing DAO package

```sh

apt-get install dao-cn10k-latest

```

Installation Demo

[<img src="doc/guides/_static/demo/install.png" style="width:400px;"/>](https://marvellembeddedprocessors.github.io/dpu-accelerator-offload/guides/gsg/install.html#installation-demo)

Running First DAO application

[<img src="doc/guides/_static/demo/run.png" style="width:400px;"/>](https://marvellembeddedprocessors.github.io/dpu-accelerator-offload/guides/applications/smart-nic.html#application-running-demo)
