/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __PACKET_H__
#define __PACKET_H__

#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_flow.h>
#include <rte_hexdump.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_thread.h>

#include <dao_assert.h>
#include <dao_flow.h>
#include <dao_log.h>
#include <dao_version.h>

#define BURST_SIZE 255

typedef struct dao_flow *(*flow_test_create_t)(uint16_t portid, int test_val_idx);

struct dao_flow *ovs_flow_test_create(uint16_t portid, int test_val_idx);
struct dao_flow *default_flow_test_create(uint16_t portid, int test_val_idx);
struct dao_flow *basic_flow_test_create(uint16_t portid, int test_val_idx);
int sample_packet(struct rte_mempool *mbp, struct rte_mbuf **pkts);
int validate_flow_match(struct rte_mbuf *pkt, uint16_t mark);

#endif /* __PACKET_H__ */
