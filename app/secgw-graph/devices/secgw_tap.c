/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <secgw.h>
#include <nodes/rxtx/rxtx_node_priv.h>

/* Structure definitions */
typedef struct {
	secgw_device_t sdev;
	uint32_t n_rxq_desc;
	uint32_t n_txq_desc;
	uint32_t n_rxq;
	uint32_t n_txq;
	struct rte_eth_conf dev_tap_conf;
} secgw_tap_t;

/* Global Variable definitions */
dao_portq_group_t tap_dpq = DAO_PORTQ_GROUP_INITIALIZER;
dao_port_group_t tap_dpg = DAO_PORT_GROUP_INITIALIZER;

/* Functions */
static inline secgw_tap_t *
secgw_tap_cast(secgw_device_t *sdev)
{
	/* Temp: Just to verify offsetof is working */
	assert(!offsetof(secgw_tap_t, sdev));

	return(
	(secgw_tap_t *)((uint8_t *)sdev - offsetof(secgw_tap_t, sdev)));
}

static uint32_t overhead_len(uint32_t max_rx_pktlen, uint16_t max_mtu)
{
	uint32_t overhead_len;

	if (max_mtu != UINT16_MAX && (max_rx_pktlen > max_mtu))
		overhead_len = max_rx_pktlen - max_mtu;
	else
		overhead_len = RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;

	return overhead_len;
}

static int secgw_tap_configure(secgw_device_t *sdev, secgw_device_register_conf_t *conf)
{
	static struct rte_eth_conf secgw_def_port_conf = {
	.rxmode = {
			.mq_mode = RTE_ETH_MQ_RX_RSS,
		},
	.rx_adv_conf = {
			.rss_conf = {
					.rss_key = NULL,
					.rss_hf = RTE_ETH_RSS_IP,
				},
		},
	.txmode = {
			.mq_mode = RTE_ETH_MQ_TX_NONE,
		},
	};
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf *ptap_conf;
	secgw_tap_t *tap = NULL;
	uint32_t rx_pktlen;
	int rc = 0;

	dao_dbg("Configuring device(%d): %s", sdev->dp_port_id, sdev->dev_name);

	/* Fetch app specific device structure */
	tap = secgw_tap_cast(sdev);
	ptap_conf = &tap->dev_tap_conf;

	/* get underlying dp port id and get device_info */
	rte_eth_dev_info_get(sdev->dp_port_id, &dev_info);

	memcpy(ptap_conf, &secgw_def_port_conf, sizeof(struct rte_eth_conf));

	/* Set rx_pktlen and MTU in ptap_conf->*/
	rx_pktlen = RTE_MIN((uint32_t)RTE_ETHER_MAX_LEN /*TODO*/, dev_info.max_rx_pktlen);

	ptap_conf->rxmode.mtu = rx_pktlen -
					overhead_len(dev_info.max_rx_pktlen, dev_info.max_mtu);

	dao_dbg("rxmode.mtu: %u, rx_pktlen: %u, ovrhd_len: %u", ptap_conf->rxmode.mtu, rx_pktlen,
		overhead_len(dev_info.max_rx_pktlen, dev_info.max_mtu));

	if (ptap_conf->rxmode.mtu > RTE_ETHER_MTU) {
		//conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
		dao_dbg("multi-seg offload enabled");
	}
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		ptap_conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	ptap_conf->rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;

	/* Determine RXQs and TXQs that can be configured */
	tap->n_rxq = RTE_MIN(conf->num_rx_queues, dev_info.max_rx_queues);
	tap->n_txq = RTE_MIN(conf->num_tx_queues, dev_info.max_tx_queues);
	dao_dbg("Possible: n_rxq: %d, n_txq: %d ", tap->n_rxq, tap->n_txq);

	/* TODO: adjust desc based rte_eth_dev_info */
	tap->n_txq_desc = conf->num_tx_desc;
	tap->n_rxq_desc = conf->num_rx_desc;

	/* configure device */
	rc = rte_eth_dev_configure(sdev->dp_port_id, tap->n_rxq, tap->n_txq, ptap_conf);
	if (rc < 0)
		DAO_ERR_GOTO(rc, dev_configure_fail, "%s: tap_dev_configure() failed with err: %d",
			     sdev->dev_name, rc);

	return 0;

dev_configure_fail:
	return errno;
}

static int secgw_tap_queue_setup(secgw_device_t *sdev)
{
	secgw_main_t *elm = secgw_get_main();
	struct rte_mempool *app_mp = NULL;
	struct rte_eth_dev_info dev_info;
	secgw_tap_t *tap = NULL;
	secgw_numa_id_t *numa = NULL;
	uint32_t iter = 0;
	int rc = -1;

	dao_dbg("Configuring queue setup for (%d): %s", sdev->dp_port_id, sdev->dev_name);

	/* Fetch app specific device structure */
	tap = secgw_tap_cast(sdev);

	/* get underlying dp port id and get device_info */
	rte_eth_dev_info_get(sdev->dp_port_id, &dev_info);

	/* TXQ setup */
	for (iter = 0; iter < tap->n_txq; iter++) {
		dao_dbg("\t Configuring Txq: %d", iter);
		rc = rte_eth_tx_queue_setup(sdev->dp_port_id, iter, tap->n_txq_desc,
					    rte_eth_dev_socket_id(sdev->dp_port_id),
					    &dev_info.default_txconf);
		if (rc < 0)
			DAO_ERR_GOTO(-EINVAL, txq_setup_fail, "Port: %s, tx_queue_setup %d fails ",
				     sdev->dev_name, sdev->dp_port_id);
	}
	/* Grab mempool for device */
	app_mp = NULL;
	STAILQ_FOREACH(numa, &elm->secgw_main_numa_list, next_numa_id) {
		if (numa->numa_id == rte_eth_dev_socket_id(sdev->dp_port_id))
			app_mp = (struct rte_mempool *)numa->user_arg;
	}
	if (!app_mp) {
		DAO_ERR_GOTO(-EINVAL, txq_setup_fail, "No mempool allocated for numa_id: %d",
			     rte_eth_dev_socket_id(sdev->dp_port_id));
	}

	/* RXQ setup */
	for (iter = 0; iter < tap->n_rxq; iter++) {
		dao_dbg("\t Configuring rxq: %d", iter);
		rc = rte_eth_rx_queue_setup(sdev->dp_port_id, iter, tap->n_rxq_desc,
					    rte_eth_dev_socket_id(sdev->dp_port_id),
					    &dev_info.default_rxconf, app_mp);
		if (rc < 0)
			DAO_ERR_GOTO(-EINVAL, rxq_setup_fail, "Port: %s, rx_queue_setup %d fails ",
				     sdev->dev_name, sdev->dp_port_id);
	}

	return 0;

rxq_setup_fail:
txq_setup_fail:
	return -1;
}

static secgw_device_t *secgw_tap_alloc(void)
{
	secgw_tap_t *tap = NULL;

	tap = malloc(sizeof(secgw_tap_t));
	if (!tap) {
		dao_err("secge_tap alloc fails");
		return NULL;
	}
	memset(tap, 0, sizeof(*tap));

	return &tap->sdev;
}

static int secgw_tap_dealloc(secgw_device_t *sdev)
{
	secgw_tap_t *tap = NULL;

	if (!sdev)
		return -1;

	tap = secgw_tap_cast(sdev);

	free(tap);

	return 0;
}

static int secgw_tap_close(secgw_device_t *sdev)
{
	return rte_eth_dev_close(sdev->dp_port_id);
}

int
secgw_register_tap(secgw_device_t **ppdev, secgw_device_register_conf_t *conf)
{
	struct rte_eth_dev_info devinfo;
	secgw_device_t *sdev = NULL;
	uint32_t port_num;
	int rc = -1;

	rte_eth_dev_info_get(conf->dp_port_id, &devinfo);

	/* Allocate new tap */
	sdev = secgw_tap_alloc();
	if (!sdev) {
		dao_err("secgw_tap_alloc() failed");
		goto tap_failure;
	}

	memset(sdev, 0, sizeof(secgw_device_t));

	/** Create port_group for first tap seen */
	if (tap_dpg == DAO_PORT_GROUP_INITIALIZER) {
		if (dao_port_group_create(
			conf->name, conf->total_devices, &tap_dpg) < 0) {
			dao_err("port_group %s create failed", conf->name);
			return -1;
		}
		dao_dbg("port_group \"%s\" created with num_devices: %u",
			conf->name, conf->total_devices);
	}

	if (tap_dpq == DAO_PORTQ_GROUP_INITIALIZER) {
		/** Create portq group for tap based graph node */
		if (dao_portq_group_create(conf->name, conf->num_workers,
					   conf->num_workers *
					   conf->total_devices, &tap_dpq) < 0) {
			dao_err("port_queue_group %s create failed", conf->name);
			return -1;
		}
		dao_dbg("port_queue_group \"%s\" created with num_workers: %u: num_device: %u",
			conf->name, conf->num_workers, conf->total_devices);
	}
	sdev->port_group = tap_dpg;
	sdev->portq_group = tap_dpq;
	sdev->dp_port_id = conf->dp_port_id;
	sdev->device_index = conf->device_index;
	sdev->paired_device_index = -1;

	dao_port_group_port_get_num(tap_dpg, &port_num);

	snprintf(sdev->dev_name, SECGW_DEVICE_NAMELEN, "%s%d", conf->name, port_num);

	rc = secgw_tap_configure(sdev, conf);
	if (rc < 0) {
		dao_err("%s device configure failed with error-code: %d", sdev->dev_name, rc);
		goto tap_dealloc;
	}
	dao_dbg("Configured: %s", sdev->dev_name);

	rc = secgw_tap_queue_setup(sdev);
	if (rc < 0) {
		dao_err("secgw_tap_queue_setup failure");
		goto tap_close;
	}
	dao_dbg("Queue setup done for: %s", sdev->dev_name);

	rc = dao_port_group_port_add(sdev->port_group,
				     (dao_port_t)sdev->device_index,
				     &sdev->port_index);
	if (rc < 0) {
		dao_err("dao_port_group_port_add fails");
		goto tap_dealloc;
	}

	if (ppdev)
		*ppdev = sdev;

	return 0;
tap_close:
	secgw_tap_close(sdev);

tap_dealloc:
	secgw_tap_dealloc(sdev);

tap_failure:
	return -1;
}

/** active taps: which are paired with ethdevs. Add active tap devies to
 * respective port queue group for [tapdev, queue] polling in tap based source
 * node
 */
int
secgw_register_active_tap(secgw_device_t *sdev, uint32_t num_workers)
{
	secgw_tap_t *edev = NULL;
	dao_portq_t portq;
	int32_t index;
	uint32_t iter;

	if (tap_dpq == DAO_PORTQ_GROUP_INITIALIZER) {
		dao_err("tap portq group not initialized");
		return -1;
	}
	dao_dbg("activa_tap: %s, dp_port_id: %u, di: %u", sdev->dev_name,
		sdev->dp_port_id, sdev->device_index);

	edev = secgw_tap_cast(sdev);
	for (iter = 0; iter < RTE_MIN(num_workers, edev->n_rxq); iter++) {
		portq.port_id = sdev->device_index;
		portq.rq_id = iter;
		if (dao_portq_group_portq_add(sdev->portq_group, iter, &portq, &index) < 0) {
			dao_err("portq group add[%u, %u] failed", portq.port_id, portq.rq_id);
			continue;
		}
		dao_dbg("portq group [%u, %u] added to core: %d at index : %u",
			portq.port_id, portq.rq_id, iter, index);
	}
	sdev->tx_node = secgw_taptx_node_get();
	return 0;
}
