..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

************************
Getting Started with OVS
************************

This document provides a step-by-step guide to get started with Open vSwitch (OVS)
on Marvell CN10K platform.


Building and Installing OVS
===========================

There are two ways to get OVS running on the CN10K platform:

1. Use the OVS package from Marvell's distribution repository
2. Build OVS from source

Installing OVS from the distribution repository
-----------------------------------------------

.. code-block:: console

 # apt-get install ovs-3.3.0-cn10k

To remove the installed package:

.. code-block:: console

 # apt-get remove ovs-3.3.0-cn10k

Clear cache:

.. code-block:: console

 # rm /var/cache/apt/archives/ovs-3.3*

Building OVS from source
------------------------

OVS depends on DPDK for packet processing. The following steps describe how to build OVS with
DPDK support.

Building and installing DPDK
````````````````````````````

Before building OVS, DPDK should be built and installed. The following steps describe how to
build and install DPDK.

.. code-block:: console

 # meson build --cross marvell-ci/build/config/arm64_cn10k_linux_gcc-marvell --prefix=<PATH_TO_INSTALL_DIR>
 # ninja -C build
 # ninja -C build install

Check if libdpdk can be found by pkg-config:

.. code-block:: console

 # pkg-config --modversion libdpdk

The above command should return the DPDK version installed. If not found, export the path to the installed DPDK libraries:

.. code-block:: console

 # export PKG_CONFIG_LIBDIR=<DPDK_INSTALL_DIR>/lib/pkgconfig

Get the OVS sources
```````````````````
Get the OVS sources by cloning the repository or by download from
`sources <http://www.openvswitch.org/download/>`_

.. code-block:: console

 # git clone https://github.com/openvswitch/ovs
 # git checkout branch-3.3
 # ./boot.sh

Apply custom patches
````````````````````

OVS custom patches are available as part of DAO repository.

:ref:`Cloning DAO repository<getting_dao_sources>`

Apply the patches:

.. code-block:: console

 # patch -p1 < <DAO_repo>patches/ovs/v3.3.0/*.patch

Compilation
```````````

For OVS to use DPDK, it should be configured to build against the DPDK library (--with-dpdk).

* Ensure the standard OVS requirements, described in
  `Build Requirements <https://docs.openvswitch.org/en/latest/intro/install/general/#general-build-reqs>`_,
  are installed

* Ensure toolchain is setup

* Bootstrap, if required, as described in
  `Bootstrapping <https://docs.openvswitch.org/en/latest/intro/install/general/#general-bootstrapping>`_

* Configure the package using the ``--with-dpdk`` flag

* If OVS to consume DPDK static libraries (also equivalent to --with-dpdk=yes ):

.. code-block:: console

 # ./configure --host=aarch64-marvell-linux-gnu --prefix=<PATH_OVS_INSTALL_DIR>  --with-dpdk=static

* If OVS to consume DPDK shared libraries:

.. code-block:: console

 # ./configure --host=aarch64-marvell-linux-gnu --prefix=<PATH_OVS_INSTALL_DIR> --with-dpdk=shared

* Once configured properly, build and install the binaries to prefixed directory

.. code-block:: console

 # make
 # make install

Launching OVS
=============

Hugepage setup
--------------

.. code-block:: console

 # mkdir /dev/huge
 # mount -t hugetlbfs none /dev/huge
 # echo 24 > /proc/sys/vm/nr_hugepages
 # echo 512 >/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

.. _setting_up_ovs_env:

Binding the required devices
----------------------------

In most common scenarios OVS binds RPM (NIX) PFs and port representors in a bridge to
provide switching between the represented ports (actual SDP/RPM PFs/VFs) and enabling
across the wire.

Representor ports are backed by ESW RVU device, which acts as an backend in enabling
communication between port representors and represented ports.

Check for device ID ``0xa0e0`` viz ESW PF and bind to vfio-pci

.. code-block:: console

 # lspci | grep a0e0
 0002:1c:00.0 Ethernet controller: Cavium, Inc. Device a0e0 (rev 50)

 # dpdk-devbind.py -b vfio-pci 0002:1c:00.0

.. note :: In case no device found with ``lspci | grep a0e0`` means incompatible firmware
 is flashed on the board.

Check for device ID ``0xa063`` viz RPM (NIX) PF and bind to vfio-pci (Optional)

.. code-block:: console

 # dpdk-devbind.py -s
 0002:02:00.0 'Octeon Tx2 RVU Physical Function a063' if=eth1 drv=rvu_nicpf unused=vfio-pci

 # dpdk-devbind.py -b vfio-pci 0002:02:00.0

.. _launching_ovs:

Setting up OVS directory and the path
-------------------------------------

Following steps assume OVS is installed at /usr/local. Replace the same with
<PATH_OVS_INSTALL_DIR> for different path.

.. note :: OVS launching fails if <PATH_OVS_INSTALL_DIR> is NFS path.

* Create directory for storing of openvswitch scripts

.. code-block:: console

 # mkdir -p /usr/local/var/run/openvswitch/
 # mkdir -p /usr/local/etc/openvswitch/

* Update default PATH with OVS scripts and binaries

.. code-block:: console

 # export PATH=$PATH:/usr/local/share/openvswitch/scripts:/usr/local/sbin/:/usr/local/bin/

* Generation of database socket file(db.sock)

.. code-block:: console

 # ovsdb-tool create /usr/local/etc/openvswitch/conf.db /usr/local/share/openvswitch/vswitch.ovsschema
 # export DB_SOCK=/usr/local/var/run/openvswitch/db.sock

* Set ovsdb file and vswtichd log file path

.. code-block:: console

 # OVSDB_FILE="/usr/local/etc/openvswitch/conf.db"
 # OVS_LOG="/tmp/ovs-vswitchd.log"

* Running database server (ovsdb server)

.. code-block:: console

 # ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
                --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
                --pidfile --detach

 # ovs-ctl start --db-sock=/usr/local/var/run/openvswitch/db.sock \
                --db-file="${OVSDB_FILE}"  --db-schema=/usr/local/var/run/openvswitch/db.sock \
                --no-ovs-vswitchd

* | Configuring ovs to use DPDK
  | With ``other_config:dpdk-extra=`` we can provide DPDK EAL args

.. code-block:: console

 # ovs-vsctl --no-wait init
 # ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-init=true \
               other_config:dpdk-socket-mem="1024"  other_config:hw-offload=true \
               other_config:dpdk-extra="--vfio-vf-token=\"9d75f7af-606e-47ff-8ae4-f459fce4a422\" \
               --allow=\"0002:02:00.0\""

* Running openvwswitch Daemon

.. code-block:: console

 # ovs-vswitchd unix:$DB_SOCK --pidfile --detach --log-file=$OVS_LOG

* Raise log levels

.. code-block:: console

 # /usr/local/bin/ovs-appctl vlog/set netdev_dpdk:file:dbg
 # /usr/local/bin/ovs-appctl vlog/set netdev_offload_dpdk:file:dbg
 # /usr/local/bin/ovs-appctl vlog/set netdev_dpdk:console:info

.. _creating_bridge:

Creating bridge and binding ports
---------------------------------

.. code-block:: console

 # ovs-vsctl add-br br0 -- set Bridge br0 datapath_type=netdev
 # ovs-vsctl add-port br0 e0_pf -- set Interface e0_pf type=dpdk options:dpdk-devargs=<PCI BDF>

 (Ex. ovs-vsctl add-port br0 e0_pf -- set Interface e0_pf type=dpdk options:dpdk-devargs=0002:02:00.0)

* Creating representor ports and binding them to the bridge

.. code-block:: console

 # ovs-vsctl add-port br0 e0_vf_rep0 -- set Interface e0_vf_rep0 type=dpdk 'options:dpdk-devargs=0002:1c:00.0,representor=pf1vf0'
 # ovs-vsctl add-port br0 e0_vf_rep1 -- set Interface e0_vf_rep1 type=dpdk 'options:dpdk-devargs=0002:1c:00.0,representor=pf1vf1'
 # ovs-vsctl add-port br0 e0_vf_rep2 -- set Interface e0_vf_rep2 type=dpdk 'options:dpdk-devargs=0002:1c:00.0,representor=pf1vf2'

.. note :: Representors are created on ESW device 002:1c:00.0

* Display ports attached to bridge

.. code-block:: console

 # ovs-vsctl show

Following output ensures successful OVS launching:

.. code-block:: console

  ac6d388f-eb66-4cba-8f7b-55b67fed0af2
    Bridge br0
        datapath_type: netdev
        Port e0_vf_rep0
            Interface e0_vf_rep0
                type: dpdk
                options: {dpdk-devargs="0002:1c:00.0,representor=pf1vf0"}
        Port e0_vf_rep1
            Interface e0_vf_rep1
                type: dpdk
                options: {dpdk-devargs="0002:1c:00.0,representor=pf1vf1"}
        Port e0_pf
            Interface e0_pf
                type: dpdk
                options: {dpdk-devargs="0002:02:00.0"}
        Port e0_vf_rep2
            Interface e0_vf_rep2
                type: dpdk
                options: {dpdk-devargs="0002:1c:00.0,representor=pf1vf2"}
        Port br0
            Interface br0
                type: internal

.. _configure_vlan:

Configuring VLAN
================

Configuring a VLAN on a VM's representor port isolates VM traffic, ensuring that only VMs on the
same VLAN can communicate directly.

Bridge is created and ports are bind to bridge in same way as described:

:ref:`Setting up bridge and attaching ports<creating_bridge>`

Aditionally VLAN tag is configured on the representor port whose VM demands tagged traffic

.. code-block:: console

  # ovs-vsctl add-port br0 e0_vf_rep0 tag=100

Command refers to traffic comming into OVS via representor port of VM1 i.e. e0_vf_rep0 will be
untagged, while it goes out with a VLAN tag 100.

Execute `ovs-vsctl show` to confirm proper VLAN configuration

.. code-block:: console

 # ovs-vsctl show
 5c994357-8ac0-4be2-a912-b6e09d81465e
    Bridge br0
        datapath_type: netdev
        Port e0_vf_rep2
            tag: 102
            Interface e0_vf_rep2
                type: dpdk
                options: {dpdk-devargs="0002:1c:00.0,representor=pf1vf2"}
        Port e0_vf_rep0
            tag: 100
            Interface e0_vf_rep0
                type: dpdk
                options: {dpdk-devargs="0002:1c:00.0,representor=pf1vf0"}
        Port br0
            Interface br0
                type: internal
        Port e0_vf_rep1
            tag: 101
            Interface e0_vf_rep1
                type: dpdk
                options: {dpdk-devargs="0002:1c:00.0,representor=pf1vf1"}
        Port e0_pf
            Interface e0_pf
                type: dpdk
                options: {dpdk-devargs="0002:02:00.0"}

Here e0_vf_rep0, e0_vf_rep1, e0_vf_rep2 are configured with VIDs 100, 101, 102 respectively.

.. _configure_vxlan:

Configuring VxLAN
=================

The following steps configure virtual machines on two different hosts to communicate over an
overlay network using VXLAN support in OVS.

For configuring VXLAN, the setup involves two bridges: br0, which binds representor ports and
the VXLAN port configured with the remote host IP, and br1, which binds the PF/wire port for
outgoing traffic and is assigned the local IP.

Steps to configure VxLAN:

* Create internal bridge `br0`

.. code-block:: console

  # ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

* Attach representor ports:

.. code-block:: console

  # ovs-vsctl add-port br0 e0_vf_rep0 -- set Interface e0_vf_rep0 type=dpdk 'options:dpdk-devargs=0002:1c:00.0,representor=pf1vf0'
  # ovs-vsctl add-port br0 e0_vf_rep1 -- set Interface e0_vf_rep1 type=dpdk 'options:dpdk-devargs=0002:1c:00.0,representor=pf1vf1'
  # ovs-vsctl add-port br0 e0_vf_rep2 -- set Interface e0_vf_rep2 type=dpdk 'options:dpdk-devargs=0002:1c:00.0,representor=pf1vf2'

* Add a port for the VXLAN tunnel with remote host IP:

.. code-block:: console

  # ovs-vsctl add-port br0 vxlan0 \
          -- set interface vxlan0 type=vxlan options:remote_ip=172.168.1.10 options:key=5001

* Create a phy bridge `br1`

.. code-block:: console

  # ovs-vsctl --may-exist add-br br1 \
            -- set Bridge br1 datapath_type=netdev \
                -- br-set-external-id br1 bridge-id br1 \
                    -- set bridge br1 fail-mode=standalone \
                             other_config:hwaddr=00:00:00:aa:bb:cc

* Attach PF interface to br1 bridge

.. code-block:: console

  # ovs-vsctl add-port br1 e0_pf -- set Interface e0_pf type=dpdk options:dpdk-devargs=0002:02:00.0

* Configure IP to the bridge, (this is tunnel IP which peer host configures as remote IP)

.. code-block:: console

  # ip addr add 172.168.1.20/24 dev br1
  # ip link set br1 up

* Display configured bridge

.. code-block:: console

  # ovs-vsctl show
  2871351d-c700-430a-85b6-54eb9902e3f5
    Bridge br0
        datapath_type: netdev
        Port e0_vf_rep1
            Interface e0_vf_rep1
                type: dpdk
                options: {dpdk-devargs="0002:1c:00.0,representor=pf1vf1"}
        Port br0
            Interface br0
                type: internal
        Port e0_vf_rep2
            Interface e0_vf_rep2
                type: dpdk
                options: {dpdk-devargs="0002:1c:00.0,representor=pf1vf2"}
        Port e0_vf_rep0
            Interface e0_vf_rep0
                type: dpdk
                options: {dpdk-devargs="0002:1c:00.0,representor=pf1vf0"}
        Port vxlan0
            Interface vxlan0
                type: vxlan
                options: {key="5001", remote_ip="172.168.1.10"}
    Bridge br1
        fail_mode: standalone
        datapath_type: netdev
        Port br1
            Interface br1
                type: internal
        Port e0_pf
            Interface e0_pf
                type: dpdk
                options: {dpdk-devargs="0002:02:00.0"}

Here vxlan0 is the tunnel port configured with VNI 5001 and tunnel IP 172.168.1.10
