..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

System Requirements
===================

This page describes minimum system requirements for compiling and running
the DAO applications.

Compilation of DAO
------------------

Required system Tools and Libraries
* General development tools including a C compiler supporting the C11 standard,
including standard atomics, for example: GCC (version 10.0+), and pkg-config or
pkgconf required for resolving library dependencies.

For RHEL/Fedora systems these can be installed using

.. code-block:: console

 # dnf groupinstall "Development Tools"

For Ubuntu/Debian systems these can be installed using

.. code-block:: console

 # apt install build-essential

* Python 3.6 or later.

* Meson (version 0.53.0+) and ninja

meson & ninja-build packages in most Linux distributions
If the packaged version is below the minimum version, the latest versions can be
installed from Python’s “pip” repository:

.. code-block:: console

 # pip3 install meson ninja

* DPDK 23.11 or later

DPDK is a mandatory dependency for compiling DAO, as most of the applications
are based on DPDK.

Check if pkg-config able to resolve libdpdk dependency:

.. code-block:: console

 # pkg-config --modversion libdpdk

* pyelftools (version 0.22+)

For Fedora systems it can be installed using

.. code-block:: console

 # dnf install python-pyelftools

For RHEL/CentOS systems it can be installed using

.. code-block:: console

 # pip3 install pyelftools

For Ubuntu/Debian it can be installed using

.. code-block:: console

 # apt install python3-pyelftools

* Additional Libraries

Apart from DPDK, some DAO components may be dependent on some additional
libraries, those will be listed in component specific page. Presence or
absence of these dependencies will be automatically detected enabling or
disabling the relevant components appropriately.

Running DAO Applications
------------------------

For running DAO applications similar environment should be created as described
in DPDK documentation:

`<https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html#running-dpdk-applications>`_
