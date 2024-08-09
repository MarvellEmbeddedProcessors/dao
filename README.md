# Data Accelerator Offload(DAO)

Data Accelerator Offload(DAO) provides library interfaces which enable developers
to implement their own application on top of Marvell's OCTEON based data
processing units.
It also comes with applications aimed at supporting accelerated switching and
packet processing.

| Repository             | Ubuntu-22.04                                                                                                                                  | Status                                                                                                                                                                                                                        |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **_marvell-dao_**      | ![GitHub Release](https://img.shields.io/github/v/release/MarvellEmbeddedProcessors/dao?sort=date&filter=!*-devel) | [![build](https://github.com/MarvellEmbeddedProcessors/dao/actions/workflows/build.yml/badge.svg)](https://github.com/MarvellEmbeddedProcessors/dao/actions/workflows/build.yml)      |
| **_marvell-dpdk_**     | ![GitHub Release](https://img.shields.io/github/v/release/MarvellEmbeddedProcessors/marvell-dpdk?display_name=release)            | [![dependency](https://github.com/MarvellEmbeddedProcessors/marvell-dpdk-test/actions/workflows/build-cn10k.yml/badge.svg)](https://github.com/MarvellEmbeddedProcessors/marvell-dpdk-test/actions/workflows/build-cn10k.yml) |
| **_marvell-ovs_**      | ![GitHub Release](https://img.shields.io/github/v/release/MarvellEmbeddedProcessors/marvell-ovs?sort=semver&display_name=release)             | [![build-cn10k](https://github.com/MarvellEmbeddedProcessors/marvell-ovs/actions/workflows/build-cn10k.yml/badge.svg)](https://github.com/MarvellEmbeddedProcessors/marvell-ovs/actions/workflows/build-cn10k.yml)            |
| **_marvell-vpp_**      | ![GitHub Release](https://img.shields.io/github/v/release/MarvellEmbeddedProcessors/vpp?sort=semver&display_name=release)                     | [![build-cn10k](https://github.com/MarvellEmbeddedProcessors/vpp/actions/workflows/build.yml/badge.svg?branch=stable%2F2402)](https://github.com/MarvellEmbeddedProcessors/vpp/actions/workflows/build.yml)                   |
| **_marvell-oct-ep-target_**      | ![GitHub Release](https://img.shields.io/github/v/release/MarvellEmbeddedProcessors/pcie_ep_octeon_target?sort=semver&display_name=release)                     | [![build-cn10k](https://github.com/MarvellEmbeddedProcessors/pcie_ep_octeon_target/actions/workflows/build-cn10k.yml/badge.svg)](https://github.com/MarvellEmbeddedProcessors/pcie_ep_octeon_target/actions/workflows/build-cn10k.yml)                   |
| **_marvell-nginx_**      | ![GitHub Release](https://img.shields.io/github/v/release/MarvellEmbeddedProcessors/dao?sort=date&filter=nginx*)                     | [![build-cn10k](https://github.com/MarvellEmbeddedProcessors/dao/actions/workflows/build-nginx.yml/badge.svg)](https://github.com/MarvellEmbeddedProcessors/dao/actions/workflows/build-nginx.yml)                   |
| **_marvell-packages_** |                                                                                                                                               | [![Commit and deploy package](https://github.com/MarvellEmbeddedProcessors/packages/actions/workflows/push-package.yml/badge.svg)](https://github.com/MarvellEmbeddedProcessors/packages/actions/workflows/push-package.yml)  |

## Programmers Guide

https://marvellembeddedprocessors.github.io/dao/guides/

## API Reference Guide

https://marvellembeddedprocessors.github.io/dao/api/

## Release Management

https://marvellembeddedprocessors.github.io/dao/guides/contributing/release.html

## Quick start Guide

Update ubuntu repository to download dao packages

```sh

curl -fsSL https://www.marvell.com/public/repo/octeon/dao/ubuntu/v2204/dao.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/dao.gpg
curl -SsL -o /etc/apt/sources.list.d/dao.list https://www.marvell.com/public/repo/octeon/dao/ubuntu/v2204/dao.list
sudo chmod 644 /etc/apt/sources.list.d/dao.list
sudo chmod 644 /etc/apt/keyrings/dao.gpg
apt-get update

```

Installing DAO package

```sh

apt-get install dao-cn10k-devel

```

Installation Demo

[<img src="doc/guides/_static/demo/install.png" style="width:400px;"/>](https://marvellembeddedprocessors.github.io/dao/guides/gsg/install.html#installation-demo)

Running First DAO application

[<img src="doc/guides/_static/demo/run.png" style="width:400px;"/>](https://marvellembeddedprocessors.github.io/dao/guides/applications/smart-nic.html#application-running-demo)


## DAO Components Status

| Domain | Component/Solutions | Status | Documentation |
|--------|---------------------|--------|---------------|
| **DPDK** | Ethernet driver | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://doc.dpdk.org/guides/nics/cnxk.html) |
|  | Crypto driver (Symmetric/Asymmetric) | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://doc.dpdk.org/guides/cryptodevs/cnxk.html) |
|  | rte_security - Inline (IPsec/MACsec) | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://doc.dpdk.org/guides/prog_guide/rte_security.html#inline-protocol-offload) |
|  | rte_security - lookaside protocol (IPsec/TLS record) | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://doc.dpdk.org/guides/prog_guide/rte_security.html#lookaside-protocol-offload) |
|  | Eventdev driver | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://doc.dpdk.org/guides/eventdevs/cnxk.html) |
|  | Mempool driver | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://doc.dpdk.org/guides/mempool/cnxk.html) |
|  | DMA driver | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://doc.dpdk.org/guides/dmadevs/cnxk.html) |
|  | GPIO driver | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://doc.dpdk.org/guides/rawdevs/cnxk_gpio.html) |
|  | Baseband driver | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://doc.dpdk.org/guides/rawdevs/cnxk_bphy.html) |
|  | PCIe communication driver | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://doc.dpdk.org/guides/nics/cnxk.html) |
|  | ML device driver | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://doc.dpdk.org/guides/mldevs/cnxk.html) |
|  | Graph and Node library | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://doc.dpdk.org/guides/prog_guide/graph_lib.html) |
| **VPP** | VPP L2-L4 Accelerated Stack with IPSec | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://marvellembeddedprocessors.github.io/dao/guides/applications/vpp.html) |
|  | VPP TCP/UDP Accelerated Socket Library | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://wiki.fd.io/view/VPP/HostStack/VCL) |
|  | VPP TLS Transport plugin | ![](https://img.shields.io/static/v1?label=&message=WIP&color=red) | [Link](https://s3-docs.fd.io/vpp/24.10/aboutvpp/featurelist.html#tls-openssl) |
|  | VPP QUIC Stack | ![](https://img.shields.io/static/v1?label=&message=WIP&color=red) | [Link](https://s3-docs.fd.io/vpp/24.10/developer/plugins/quic.html) |
|  | SoNiC with VPP | ![](https://img.shields.io/static/v1?label=&message=Planned&color=orange) | |
|  | Snort with VPP | ![](https://img.shields.io/static/v1?label=&message=Planned&color=orange) | |
| **OVS** | HW accelerated OVS Offload | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://marvellembeddedprocessors.github.io/dao/guides/applications/ovs-offload.html) |
| **VIRTIO Emulation** | VirtIO-Net | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link 1](https://marvellembeddedprocessors.github.io/dao/guides/prog_guide/virtio_net_lib.html) <br> [Link 2](https://marvellembeddedprocessors.github.io/dao/guides/applications/virtio-l2fwd.html) |
|  | VirtIO-Crypto | ![](https://img.shields.io/static/v1?label=&message=Planned&color=orange) | |
|  | VirtIO-Block | ![](https://img.shields.io/static/v1?label=&message=Planned&color=orange) | |
| **OpenSSL** | SSL crypto Acceleration via Engine | ![](https://img.shields.io/static/v1?label=&message=WIP&color=red) | |
|  | TLS MIM Application | ![](https://img.shields.io/static/v1?label=&message=WIP&color=red) | |
|  | NGINX Proxy/TLS Proxy | ![](https://img.shields.io/static/v1?label=&message=WIP&color=red) | [Link 1](https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/) <br> [Link 2](https://marvellembeddedprocessors.github.io/dao/guides/applications/tls-proxy-nginx.html) |
|  | NGINX Load Balancer | ![](https://img.shields.io/static/v1?label=&message=WIP&color=red) | [Link](http://nginx.org/en/docs/http/load_balancing.html) |
| **AI/ML** | AI/ML Toolkit | ![](https://img.shields.io/static/v1?label=&message=Planned&color=orange) | |
|  | Inferencing application - Resnet50 Image classification | ![](https://img.shields.io/static/v1?label=&message=Planned&color=orange) | |
|  | Inferencing application - DDoS detection | ![](https://img.shields.io/static/v1?label=&message=Planned&color=orange) | |
| **Cloud Solutions** | Cilium CNI | ![](https://img.shields.io/static/v1?label=&message=WIP&color=red) | |
|  | Calico | ![](https://img.shields.io/static/v1?label=&message=WIP&color=red) | |
| **Libraries** | Netlink Helper library | ![](https://img.shields.io/static/v1?label=&message=Ready&color=green) | [Link](https://marvellembeddedprocessors.github.io/dao/guides/prog_guide/netlink_lib.html) |
|  | IPsec | ![](https://img.shields.io/static/v1?label=&message=Experimental&color=blue) | [Link](https://marvellembeddedprocessors.github.io/dao/guides/applications/secgw-graph.html#running-as-ipsec-gateway) |
|  | SmartNIC App | ![](https://img.shields.io/static/v1?label=&message=Experimental&color=blue) | [Link](https://marvellembeddedprocessors.github.io/dao/guides/applications/smart-nic.html) |
|  | Connection Tracking Library | ![](https://img.shields.io/static/v1?label=&message=WIP&color=red) | |
|  | Flow library | ![](https://img.shields.io/static/v1?label=&message=WIP&color=red) | |
|  | Key Extraction Library | ![](https://img.shields.io/static/v1?label=&message=Planned&color=orange) | |
|  | Packet Transformation | ![](https://img.shields.io/static/v1?label=&message=WIP&color=red) | |
|  | TLS offload | ![](https://img.shields.io/static/v1?label=&message=WIP&color=red) | |
|  | Protocol Parser Library | ![](https://img.shields.io/static/v1?label=&message=Planned&color=orange) | |
|  | SNORT Integration | ![](https://img.shields.io/static/v1?label=&message=Planned&color=orange) | |
|  | NAT | ![](https://img.shields.io/static/v1?label=&message=Planned&color=orange) | |
|  | Compression App | ![](https://img.shields.io/static/v1?label=&message=Planned&color=orange) | |
