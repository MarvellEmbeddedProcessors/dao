/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 * This file contains the kernel ABI definitions for the RDMA device.
 */

#ifndef RDMA_KERNEL_ABI_H
#define RDMA_KERNEL_ABI_H

#include <stdint.h>
#include <string.h>
#include <unistd.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint32_t __be32;

#define BIT_ULL(n) (1ULL << (n))

/* Device cap and port attr struct mappings */
#define rdma_device_cap octep_rdma_device_cap
#define rdma_port_attr  octep_rdma_port_attr

/* RDMA MTU Size mappings */
#define RDMA_MTU_256  OCTEP_RDMA_MTU_256
#define RDMA_MTU_512  OCTEP_RDMA_MTU_512
#define RDMA_MTU_1024 OCTEP_RDMA_MTU_1024
#define RDMA_MTU_2048 OCTEP_RDMA_MTU_2048
#define RDMA_MTU_4096 OCTEP_RDMA_MTU_4096

/* Mailbox Message Type Mappings */
#define MBOX_MSG_USER_QP_CREATE        OCTEP_RDMA_MBOX_MSG_USER_QP_CREATE
#define MBOX_MSG_USER_QP_MODIFY        OCTEP_RDMA_MBOX_MSG_USER_QP_MODIFY
#define MBOX_MSG_USER_QP_DESTROY       OCTEP_RDMA_MBOX_MSG_USER_QP_DESTROY
#define MBOX_MSG_USER_CQ_CREATE        OCTEP_RDMA_MBOX_MSG_USER_CQ_CREATE
#define MBOX_MSG_USER_CQ_DESTROY       OCTEP_RDMA_MBOX_MSG_USER_CQ_DESTROY
#define MBOX_MSG_USER_AH_CREATE        OCTEP_RDMA_MBOX_MSG_USER_AH_CREATE
#define MBOX_MSG_USER_AH_MODIFY        OCTEP_RDMA_MBOX_MSG_USER_AH_MODIFY
#define MBOX_MSG_USER_AH_DESTROY       OCTEP_RDMA_MBOX_MSG_USER_AH_DESTROY
#define MBOX_MSG_USER_PORT_STATE       OCTEP_RDMA_MBOX_MSG_USER_PORT_STATE
#define MBOX_MSG_USER_QUERY_DEVICE_CAP OCTEP_RDMA_MBOX_MSG_USER_QUERY_DEVICE_CAP
#define MBOX_MSG_USER_QUERY_PORT_ATTR  OCTEP_RDMA_MBOX_MSG_USER_QUERY_PORT_ATTR
#define MBOX_MSG_USER_PD_ADD           OCTEP_RDMA_MBOX_MSG_USER_PD_ADD
#define MBOX_MSG_USER_PD_DELETE        OCTEP_RDMA_MBOX_MSG_USER_PD_DELETE
#define MBOX_MSG_USER_MR_REGISTER      OCTEP_RDMA_MBOX_MSG_USER_MR_REGISTER
#define MBOX_MSG_USER_MR_DEREGISTER    OCTEP_RDMA_MBOX_MSG_USER_MR_DEREGISTER

/* Atomic Operation Capability Mappings */
#define RDMA_ATOMIC_NONE OCTEP_RDMA_ATOMIC_NONE
#define RDMA_ATOMIC_HCA  OCTEP_RDMA_ATOMIC_HCA
#define RDMA_ATOMIC_GLOB OCTEP_RDMA_ATOMIC_GLOB

/* RDMA Port State Mappings */
#define RDMA_PORT_NOP          OCTEP_RDMA_PORT_NOP
#define RDMA_PORT_DOWN         OCTEP_RDMA_PORT_DOWN
#define RDMA_PORT_INIT         OCTEP_RDMA_PORT_INIT
#define RDMA_PORT_ARMED        OCTEP_RDMA_PORT_ARMED
#define RDMA_PORT_ACTIVE       OCTEP_RDMA_PORT_ACTIVE
#define RDMA_PORT_ACTIVE_DEFER OCTEP_RDMA_PORT_ACTIVE_DEFER

#include <octep_dev_cap.h>
#include <octep_mbox.h>

#endif
