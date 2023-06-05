..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

Why is --prefer-static meson option required in DAO compilation?
----------------------------------------------------------------

Meson option ``--prefer-static`` is important to ensure static linkage of
dependent libraries like DPDK. Constructor declarations made in DPDK do not
function correctly when used without static linkage.

Eg. The DPDK graph library, utilized by many DAO applications, has the
uses custom nodes from the node library. However, these nodes being constructor
declarations, fail to become part of the constructed graph when DPDK is not
statically linked.
