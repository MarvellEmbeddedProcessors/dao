/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <nodes/node_priv.h>

/* Structure definitions */
typedef struct {
	RTE_MARKER cacheline0 __rte_cache_aligned;
	secgw_device_t sdev;
	uint32_t n_rxq_desc;
	uint32_t n_txq_desc;
	uint32_t n_rxq;
	uint32_t n_txq;
	struct rte_eth_conf dev_eth_conf;
} secgw_ethdev_t __rte_cache_aligned;

/* Global Variable definitions */
dao_portq_group_t ethdev_dpq = DAO_PORTQ_GROUP_INITIALIZER;
dao_port_group_t ethdev_dpg = DAO_PORT_GROUP_INITIALIZER;

/* Functions */
static inline secgw_ethdev_t *
secgw_ethdev_cast(secgw_device_t *sdev)
{
	/* Temp: Just to verify offsetof is working */
	assert(!offsetof(secgw_ethdev_t, sdev));

	return(
	(secgw_ethdev_t *)((uint8_t *)sdev - offsetof(secgw_ethdev_t, sdev)));
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

static int secgw_ethdev_configure(secgw_device_t *sdev, secgw_device_register_conf_t *conf)
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
	const struct rte_security_capability *caps, *cap;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf *peth_conf;
	secgw_ethdev_t *ethdev = NULL;
	uint32_t rx_pktlen;
	int rc = 0, iter = 0;
	void *sec_ctx;

	dao_dbg("Configuring device(%d): %s", sdev->dp_port_id, sdev->dev_name);

	/* Fetch app specific device structure */
	ethdev = secgw_ethdev_cast(sdev);
	peth_conf = &ethdev->dev_eth_conf;

	/* get underlying dp port id and get device_info */
	rte_eth_dev_info_get(sdev->dp_port_id, &dev_info);

	memcpy(peth_conf, &secgw_def_port_conf, sizeof(struct rte_eth_conf));

	/* Set rx_pktlen and MTU in peth_conf->*/
	rx_pktlen = RTE_MIN((uint32_t)RTE_ETHER_MAX_LEN /*TODO*/, dev_info.max_rx_pktlen);

	peth_conf->rxmode.mtu = rx_pktlen -
					overhead_len(dev_info.max_rx_pktlen, dev_info.max_mtu);

	dao_dbg("rxmode.mtu: %u, rx_pktlen: %u, ovrhd_len: %u", peth_conf->rxmode.mtu, rx_pktlen,
		overhead_len(dev_info.max_rx_pktlen, dev_info.max_mtu));

	if (peth_conf->rxmode.mtu > RTE_ETHER_MTU) {
		//conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
		dao_dbg("multi-seg offload enabled");
	}
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		peth_conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	peth_conf->rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;

	/* Determine RXQs and TXQs that can be configured */
	ethdev->n_rxq = RTE_MIN(conf->num_rx_queues, dev_info.max_rx_queues);
	ethdev->n_txq = RTE_MIN(conf->num_tx_queues, dev_info.max_tx_queues);
	dao_dbg("Possible: n_rxq: %d, n_txq: %d", ethdev->n_rxq, ethdev->n_txq);

	/* TODO: adjust desc based rte_eth_dev_info */
	ethdev->n_txq_desc = conf->num_tx_desc;
	ethdev->n_rxq_desc = conf->num_rx_desc;

	/* Check rte_security offloads */
	if ((dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SECURITY) &&
	    (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_SECURITY)) {
		sec_ctx = rte_eth_dev_get_sec_ctx(sdev->dp_port_id);
		caps = rte_security_capabilities_get(sec_ctx);

		while ((cap = &caps[iter++])->action != RTE_SECURITY_ACTION_TYPE_NONE) {
		/*
		 * Check Rx support for inline ESP protocol offload in tunnel mode
		 */
			if ((cap->action == RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL) &&
			    (cap->ipsec.proto == RTE_SECURITY_IPSEC_SA_PROTO_ESP) &&
			    (cap->ipsec.direction == RTE_SECURITY_IPSEC_SA_DIR_INGRESS) &&
			    (cap->ipsec.mode == RTE_SECURITY_IPSEC_SA_MODE_TUNNEL)) {
				//peth_conf->rxmode.offloads |= RTE_ETH_RX_OFFLOAD_SECURITY;
				dao_dbg("%s supports inline Rx ESP offload", sdev->dev_name);
			}
			/*
			 * Check Tx support for inline ESP protocol offload in tunnel mode
			 */
			if ((cap->action == RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL) &&
			    (cap->ipsec.proto == RTE_SECURITY_IPSEC_SA_PROTO_ESP) &&
			    (cap->ipsec.direction == RTE_SECURITY_IPSEC_SA_DIR_EGRESS) &&
			    (cap->ipsec.mode == RTE_SECURITY_IPSEC_SA_MODE_TUNNEL)) {
				//peth_conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_SECURITY;
				dao_dbg("%s supports inline Rx ESP offload", sdev->dev_name);
			}
		}
	}
	/* configure device */
	rc = rte_eth_dev_configure(sdev->dp_port_id, ethdev->n_rxq, ethdev->n_txq, peth_conf);
	if (rc < 0)
		DAO_ERR_GOTO(rc, dev_configure_fail, "%s: eth_dev_configure() failed with err: %d",
			     sdev->dev_name, rc);
	return 0;

dev_configure_fail:
	return errno;
}

static int secgw_ethdev_queue_setup(secgw_device_t *sdev)
{
	secgw_main_t *elm = secgw_get_main();
	struct rte_mempool *app_mp = NULL;
	struct rte_eth_dev_info dev_info;
	secgw_ethdev_t *ethdev = NULL;
	secgw_numa_id_t *numa = NULL;
	uint32_t iter = 0;
	int rc = -1;

	dao_dbg("Configuring queue setup for (%d): %s", sdev->dp_port_id, sdev->dev_name);

	/* Fetch app specific device structure */
	ethdev = secgw_ethdev_cast(sdev);

	/* get underlying dp port id and get device_info */
	rte_eth_dev_info_get(sdev->dp_port_id, &dev_info);

	/* TXQ setup */
	for (iter = 0; iter < ethdev->n_txq; iter++) {
		dao_dbg("\t Configuring Txq: %d", iter);
		rc = rte_eth_tx_queue_setup(sdev->dp_port_id, iter, ethdev->n_txq_desc,
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
	for (iter = 0; iter < ethdev->n_rxq; iter++) {
		dao_dbg("\t Configuring rxq: %d", iter);
		rc = rte_eth_rx_queue_setup(sdev->dp_port_id, iter, ethdev->n_rxq_desc,
					    rte_eth_dev_socket_id(sdev->dp_port_id),
					    &dev_info.default_rxconf, app_mp);
		if (rc < 0)
			DAO_ERR_GOTO(-EINVAL, rxq_setup_fail, "Port: %s, rx_queue_setup %d fails ",
				     sdev->dev_name, sdev->dp_port_id);
	}

	sdev->tx_node = secgw_ethdevtx_node_get();

	return 0;

rxq_setup_fail:
txq_setup_fail:
	return -1;
}

static secgw_device_t *secgw_ethdev_alloc(void)
{
	secgw_ethdev_t *ethdev = NULL;

	ethdev = malloc(sizeof(secgw_ethdev_t));
	if (!ethdev) {
		dao_err("secge_ethdev alloc fails");
		return NULL;
	}
	memset(ethdev, 0, sizeof(*ethdev));

	return &ethdev->sdev;
}

static int secgw_ethdev_dealloc(secgw_device_t *sdev)
{
	secgw_ethdev_t *ethdev = NULL;

	if (!sdev)
		return -1;

	ethdev = secgw_ethdev_cast(sdev);

	free(ethdev);

	return 0;
}

static int secgw_ethdev_close(secgw_device_t *sdev)
{
	return rte_eth_dev_close(sdev->dp_port_id);
}

int
secgw_register_ethdev(secgw_device_t **ppdev, secgw_device_register_conf_t *conf)
{
	uint32_t iter = 0, port_num;
	struct rte_eth_dev_info devinfo;
	secgw_device_t *sdev = NULL;
	secgw_ethdev_t *edev = NULL;
	dao_portq_t portq = {0};
	int32_t index;
	int rc = -1;

	rte_eth_dev_info_get(conf->dp_port_id, &devinfo);

	/* Allocate new ethdev */
	sdev = secgw_ethdev_alloc();
	if (!sdev) {
		dao_err("secgw_ethdev_alloc() failed");
		goto ethdev_failure;
	}

	memset(sdev, 0, sizeof(secgw_device_t));

	/** Create port_group for first ethdev seen */
	if (ethdev_dpg == DAO_PORT_GROUP_INITIALIZER) {
		if (dao_port_group_create(
			conf->name, conf->total_devices, &ethdev_dpg) < 0) {
			dao_err("port_group %s create failed", conf->name);
			return -1;
		}
		dao_dbg("port_group \"%s\" created with num_devices: %u",
			conf->name, conf->total_devices);
	}

	if (ethdev_dpq == DAO_PORTQ_GROUP_INITIALIZER) {
		/** Create portq group for ethdev based graph node */
		if (dao_portq_group_create(conf->name, conf->num_workers,
					   conf->num_workers * conf->total_devices,
					   &ethdev_dpq) < 0) {
			dao_err("port_queue_group %s \"create failed", conf->name);
			return -1;
		}
		dao_dbg("port_queue_group \"%s\" created with num_workers: %u: num_device: %u",
			conf->name, conf->num_workers, conf->total_devices);
	}
	sdev->port_group = ethdev_dpg;
	sdev->portq_group = ethdev_dpq;
	sdev->dp_port_id = conf->dp_port_id;
	sdev->device_index = conf->device_index;
	sdev->paired_device_index = -1;

	dao_port_group_port_get_num(ethdev_dpg, &port_num);

	snprintf(sdev->dev_name, SECGW_DEVICE_NAMELEN, "%s-%d", conf->name, port_num);

	rc = secgw_ethdev_configure(sdev, conf);
	if (rc < 0) {
		dao_err("%s device configure failed with error-code: %d", sdev->dev_name, rc);
		goto ethdev_dealloc;
	}
	dao_dbg("Configured: %s", sdev->dev_name);

	rc = secgw_ethdev_queue_setup(sdev);
	if (rc < 0) {
		dao_err("secgw_ethdev_queue_setup failure");
		goto ethdev_close;
	}
	dao_dbg("Queue setup done for: %s", sdev->dev_name);

	edev = secgw_ethdev_cast(sdev);
	for (iter = 0; iter < RTE_MIN(conf->num_workers, edev->n_rxq); iter++) {
		portq.port_id = sdev->device_index;
		portq.rq_id = iter;
		if (dao_portq_group_portq_add(sdev->portq_group, iter, &portq, &index) < 0) {
			dao_err("portq group add[%u, %u] failed", portq.port_id, portq.rq_id);
			continue;
		}
		dao_dbg("portq group [%u, %u] added to core: %d at index: %u",
			portq.port_id, portq.rq_id, iter, index);
	}

	rc = dao_port_group_port_add(sdev->port_group,
				     (dao_port_t)sdev->device_index,
				     &sdev->port_index);
	if (rc < 0) {
		dao_err("dao_port_group_port_add fails");
		goto ethdev_dealloc;
	}

	if (ppdev)
		*ppdev = sdev;

	return 0;
ethdev_close:
	secgw_ethdev_close(sdev);

ethdev_dealloc:
	secgw_ethdev_dealloc(sdev);

ethdev_failure:
	return -1;
}
