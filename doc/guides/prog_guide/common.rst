..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

****************
Common Libraries
****************

Introduction
============
The Common Libraries in DPU Accelerator Offload(DAO) encompass a set of fundamental
and widely used libraries that provide essential functionalities for software
development. These libraries include components such as loggers, PCI, bit
manipulation utilities. User can leverage these libraries directly to streamline
and enhance their programming tasks with DAO environment.

Libraries Details
=================

DAO Logger
----------
DAO logger APIs contains wrappers over DPDK based rte logger. It has API for
different log levels.

DAO Utilities
-------------
It includes some useful utilities like bit manipulation, effective memory
interfaces for efficient implementation.

DAO DMA
-------
DAO DMA library was an abstract layer between DPDK DMA PMD and Virtio application.
Provides set of APIs to handle different DMA operations.

DAO Bitmap Helper
-----------------
DAO bitmap helper provides abstracted APIs to setup a bitmap, get a free index and
return the index back to bitmap.

DAO Assert Helper
-----------------
DAO assert helper provides macros for assertions in user test cases. These assertions can
be normal i.e. reporting as an error, or fatal i.e. causing test to abort.
