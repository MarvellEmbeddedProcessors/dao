..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

************************
Getting Started with OVS
************************

Compiling Open vSwitch with DPDK
================================

Building and installing DPDK
----------------------------

Get the DPDK sources, build and install the library

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

Building and Installing OVS
===========================

Get the sources
---------------
Get the OVS sources by cloning the repository or by download from
`sources <http://www.openvswitch.org/download/>`_

.. code-block:: console

 # git clone https://github.com/openvswitch/ovs
 # git checkout master
 # ./boot.sh

Compilation
-----------

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

* Creating bridge and attaching Ethernet PF port

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
