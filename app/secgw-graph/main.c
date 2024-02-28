/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <nodes/node_api.h>
#include <cli_api.h>
#include <getopt.h>

#define SECGW_MEMPOOL_CACHE_SIZE 256

#define SECGW_RXQ_NUM_DESC 2048
#define SECGW_TXQ_NUM_DESC 2048

/* To support at least 8 ports */
#define SECGW_MEMPOOL_NUM_MBUFS (SECGW_RXQ_NUM_DESC * 8)

typedef struct {
	struct scli_conn_params cli_conn_param;
	char *cli_script_file_name;
	bool enable_graph_stats;
} secgw_command_args_t;

static dao_port_group_t edpg = DAO_PORT_GROUP_INITIALIZER;
static dao_port_group_t tdpg = DAO_PORT_GROUP_INITIALIZER;
static secgw_command_args_t *secgw_command_args;
static const char usage[] = "%s <eal-args> -- -s CLI_FILE [-i CLI_CLIENT [-p CLI_CLIENT_PORT] [--enable-graph-stats] "
			    "[--help]\n";

static int
start_devices(void)
{
	struct dao_ds dev_str = DS_EMPTY_INITIALIZER;
	char link_status[RTE_ETH_LINK_MAX_STR_LEN];
	secgw_device_t *sdev = NULL;
	struct rte_eth_link link;
	dao_port_t port;
	int iter;

	if (dao_port_group_get_by_name(SECGW_ETHDEV_PORT_GROUP_NAME, &edpg) < 0)
		return -1;

	DAO_PORT_GROUP_FOREACH_PORT(edpg, port, iter)
	{
		sdev = secgw_get_device(port);

		rte_eth_dev_start(sdev->dp_port_id);
		rte_eth_promiscuous_enable(sdev->dp_port_id);
		rte_eth_dev_set_link_up(sdev->dp_port_id);
		secgw_dbg("started device: %s", sdev->dev_name);
	}

	if (dao_port_group_get_by_name(SECGW_TAP_PORT_GROUP_NAME, &edpg) < 0)
		return -1;

	DAO_PORT_GROUP_FOREACH_PORT(edpg, port, iter)
	{
		sdev = secgw_get_device(port);

		rte_eth_dev_start(sdev->dp_port_id);
		rte_eth_promiscuous_enable(sdev->dp_port_id);
		rte_eth_dev_set_link_up(sdev->dp_port_id);
		secgw_dbg("started device: %s", sdev->dev_name);
	}
	for (iter = 0; iter < secgw_num_devices_get(); iter++) {
		sdev = secgw_get_device(iter);
		dao_ds_put_cstr(&dev_str, sdev->dev_name);
		rte_eth_link_get(sdev->dp_port_id, &link);
		dao_ds_put_cstr(&dev_str, " LINK: ");
		rte_eth_link_to_str(link_status, sizeof(link_status), &link);
		dao_ds_put_cstr(&dev_str, link_status);
		if (rte_eth_promiscuous_get(sdev->dp_port_id))
			dao_ds_put_cstr(&dev_str, ", Promisc: ON ");
		else
			dao_ds_put_cstr(&dev_str, ", Promisc: OFF ");

		secgw_dbg("%s", dao_ds_cstr(&dev_str));
		dao_ds_clear(&dev_str);
	}
	dao_ds_destroy(&dev_str);

	return 0;
}

static int
connect_interface_output_next_nodes(void)
{
	secgw_device_t *sdev = NULL;
	int iter;

	for (iter = 0; iter < secgw_num_devices_get(); iter++) {
		sdev = secgw_get_device(iter);
		/* Add only that device tx node which has valid tx_node set
		 */
		if (sdev->tx_node)
			secgw_node_interface_out_attach_tx_node(sdev, sdev->tx_node);
	}

	return 0;
}

/* Register all devices aka ethdevs, taps, virtio, etc */
static int
register_devices(void)
{
	char _dev_name[36], deviceid_name[64], *tstr = NULL;
	secgw_device_main_t *sdm = secgw_get_device_main();
	secgw_device_register_conf_t dev_reg_conf = {0};
	uint16_t iter = 0, total_devices;
	struct rte_eth_dev_info devinfo;
	secgw_device_t *sdev = NULL;
	char *dev_name = NULL;
	int rc = -1;

	if (!sdm)
		return -1;

	dev_name = (char *)_dev_name;
	total_devices = rte_eth_dev_count_avail();
	dao_dbg("Total available devices: %d detected", total_devices);

	if (total_devices < 1) {
		dao_err("No valid ethdev detected");
		return -1;
	}

	dev_reg_conf.num_rx_desc = SECGW_RXQ_NUM_DESC;
	dev_reg_conf.num_tx_desc = SECGW_TXQ_NUM_DESC;
	dev_reg_conf.total_devices = total_devices;
	dev_reg_conf.num_workers = dao_workers_num_workers_get();

	/** Check how many physical and tap devices present */
	RTE_ETH_FOREACH_DEV(iter) {
		if (!rte_eth_dev_is_valid_port(iter))
			continue;

		memset(&devinfo, 0, sizeof(struct rte_eth_dev_info));

		rte_eth_dev_info_get(iter, &devinfo);

		/* See if room present to new device */
		if (secgw_num_devices_get() >= (sdm->max_num_devices_allocated - 1)) {
			sdm->devices =
				realloc(sdm->devices,
					(sizeof(secgw_device_t) *
					 (sdm->max_num_devices_allocated + SECGW_REALLOC_NUM)));
			if (!sdm->devices) {
				dao_err("realloc fails");
				return -1;
			}
			sdm->max_num_devices_allocated += SECGW_REALLOC_NUM;
		}
		dev_reg_conf.dp_port_id = iter;
		dev_reg_conf.device_index = secgw_num_devices_get();

		if (strstr(devinfo.driver_name, "tap")) {
			dev_reg_conf.name = (const char *)SECGW_TAP_PORT_GROUP_NAME;
			dev_reg_conf.device_prefix_name = (const char *)SECGW_TAP_PORT_GROUP_NAME;
			/*
			 * tap driver insist to have equal number of rxqs and txqs
			 * So no tap queue for Main-core for now
			 */
			dev_reg_conf.num_rx_queues = dao_workers_num_workers_get();
			dev_reg_conf.num_tx_queues = dao_workers_num_workers_get();
			if (secgw_register_tap(&sdm->devices[secgw_num_devices_get()],
					       &dev_reg_conf) < 0) {
				dao_err("secgw_register_tap failed");
				continue;
			}
		} else {
			dev_reg_conf.name = (const char *)SECGW_ETHDEV_PORT_GROUP_NAME;
			dev_reg_conf.device_prefix_name =
				(const char *)SECGW_ETHDEV_PORT_GROUP_NAME;
			tstr = strstr(rte_dev_bus_info(devinfo.device), "device_id");
			rc = -1;
			if (tstr)
				rc = sscanf(tstr, SECGW_PCI_DEV_STR, deviceid_name);

#define _(id, bus, str)									\
			else if (!strcmp(deviceid_name, bus)) {				\
				strcpy(dev_name, str);					\
			}

			if (rc < 0)
				strcpy(dev_name, "eth");

			foreach_octeon_device_bus_info
#undef _
			dev_reg_conf.device_prefix_name = (const char *)dev_name;
			dev_reg_conf.num_rx_queues = dao_workers_num_workers_get();
			dev_reg_conf.num_tx_queues = dao_workers_num_workers_get();
			if (secgw_register_ethdev(&sdm->devices[sdm->n_devices], &dev_reg_conf) <
			    0) {
				dao_err("secgw_register_ethdev failed");
				continue;
			}
			/* Disable inline IPsec for SDP devices */
			if (strstr((sdm->devices[sdm->n_devices])->dev_name, "sdp")) {
				(sdm->devices[sdm->n_devices])->device_flags &=
					~SECGW_HW_RX_OFFLOAD_INLINE_IPSEC;
				(sdm->devices[sdm->n_devices])->device_flags &=
					~SECGW_HW_TX_OFFLOAD_INLINE_IPSEC;
			}
		}
		sdm->n_devices++;
		sdev = secgw_get_device(dev_reg_conf.device_index);
		RTE_VERIFY(sdev->dp_port_id == sdev->device_index);
		secgw_dbg("Added device: %s at index: %u, port_index: %d, port_id: %u",
			  sdev->dev_name, sdev->device_index, sdev->port_index, sdev->dp_port_id);
	}
	return (secgw_num_devices_get());
}

static int
pair_tap_to_ethdev(void)
{
	int32_t ports[RTE_MAX_ETHPORTS];
	struct rte_ether_addr ether;
	secgw_device_t *sdev = NULL;
	uint32_t n_ethdev, n_tapdev;
	uint32_t n_common;
	dao_port_t port;
	int32_t iter, i;

	if (dao_port_group_get_by_name(SECGW_ETHDEV_PORT_GROUP_NAME, &edpg) < 0)
		return -1;

	if (dao_port_group_get_by_name(SECGW_TAP_PORT_GROUP_NAME, &tdpg) < 0)
		return -1;

	RTE_VERIFY(!dao_port_group_port_get_num(edpg, &n_ethdev));
	RTE_VERIFY(!dao_port_group_port_get_num(tdpg, &n_tapdev));

	n_common = RTE_MIN(n_ethdev, n_tapdev);

	if (!n_common) {
		dao_err("No pairing possible [n_tapdev: %u, n_ethdev: %u]", n_tapdev, n_ethdev);
		return -1;
	}

	memset(ports, 0, sizeof(ports));

	/* Pair ethdevs to tap */
	if (n_ethdev >= n_tapdev) {
		i = 0;
		DAO_PORT_GROUP_FOREACH_PORT(edpg, port, iter)
			ports[i++] = port;
		i = 0;
		DAO_PORT_GROUP_FOREACH_PORT(tdpg, port, iter)
		{
			sdev = secgw_get_device(port);
			sdev->paired_device_index = ports[i];

			/* Add tap to portq for node polling */
			secgw_register_active_tap(sdev, dao_workers_num_workers_get());

			memset(&ether, 0, sizeof(struct rte_ether_addr));

			rte_eth_macaddr_get(secgw_get_device(port)->dp_port_id, &ether);
			rte_eth_dev_default_mac_addr_set(secgw_get_device(ports[i])->dp_port_id,
							 &ether);

			sdev = secgw_get_device(ports[i]);
			sdev->paired_device_index = port;
			secgw_info("%s paired with %s", sdev->dev_name,
				   (secgw_get_device(sdev->paired_device_index))->dev_name);
			i++;
		}
	} else {
		i = 0;
		DAO_PORT_GROUP_FOREACH_PORT(tdpg, port, iter)
			ports[i++] = port;

		i = 0;
		DAO_PORT_GROUP_FOREACH_PORT(edpg, port, iter)
		{
			memset(&ether, 0, sizeof(struct rte_ether_addr));
			sdev = secgw_get_device(port);
			sdev->paired_device_index = ports[i];

			sdev = secgw_get_device(ports[i]);
			sdev->paired_device_index = port;
			secgw_info("%s paired with %s", sdev->dev_name,
				   (secgw_get_device(sdev->paired_device_index))->dev_name);
			/* Add tap to portq for node polling */
			secgw_register_active_tap(sdev, dao_workers_num_workers_get());

			rte_eth_macaddr_get(secgw_get_device(ports[i])->dp_port_id, &ether);
			rte_eth_dev_default_mac_addr_set(secgw_get_device(port)->dp_port_id,
							 &ether);
			i++;
		}
	}
	return 0;
}

static int
enable_feature_arc(void)
{
	dao_port_t port;
	int iter = 0;

	/* Anything coming on tap device should be punted to paired eth-dev device */

	if (ip_feature_arcs_register(secgw_num_devices_get())) {
		dao_err("IP feature arc initialization failed");
		return -1;
	}

	if (dao_port_group_get_by_name(SECGW_ETHDEV_PORT_GROUP_NAME, &edpg) < 0) {
		dao_err("%s port group not found", SECGW_ETHDEV_PORT_GROUP_NAME);
		return -1;
	}

	ip_feature_punt_add(secgw_portmapper_node_get());

	/* Add interface-output and error-drop features to "ip4-output" feature */
	ip_feature_output_add(secgw_ipsec_policy_output_node_get(), NULL, NULL);
	ip_feature_output_add(secgw_interface_out_node_get(),
			      secgw_ipsec_policy_output_node_get()->name, NULL);
	ip_feature_output_add(secgw_errordrop_node_get(), secgw_interface_out_node_get()->name,
			      NULL);

	ip_feature_local_add(secgw_portmapper_node_get(), NULL, NULL);

	/* Enable Punting on Ethernet devices which has IP enable
	 * TODO: Move feature enable to control plane addition of local IP
	 */
	DAO_PORT_GROUP_FOREACH_PORT(edpg, port, iter)
	{
		ip_feature_punt_enable(secgw_portmapper_node_get(), port, 0);
		ip_feature_output_enable(secgw_interface_out_node_get(), port, 0);
		ip_feature_output_enable(secgw_errordrop_node_get(), port, 0);
		ip_feature_local_enable(secgw_portmapper_node_get(), port, 0);
	}

	return 0;
}

static int initialize_command_line_args(void)
{
	struct scli_conn_params *cparam = NULL;

	if (!secgw_command_args) {
		secgw_command_args = malloc(sizeof(*secgw_command_args));

		if (!secgw_command_args) {
			dao_err("malloc fails");
			return -1;
		}
		memset(secgw_command_args, 0, sizeof(*secgw_command_args));

		cparam = &secgw_command_args->cli_conn_param;

		cparam->welcome = "\n\t\tWELCOME to Security Gateway App!\n\n";
		cparam->prompt = "secgw-graph> ";
		cparam->addr = "127.0.0.1";
		cparam->port = 8086;
		cparam->buf_size = 1024 * 1024;
		cparam->msg_in_len_max = 1024;
		cparam->msg_out_len_max = 1024 * 1024;
		cparam->msg_handle = scli_process;
		cparam->msg_handle_arg = NULL;

		return 0;
	}
	return -1;
}

static int
parse_command_line_args(int argc, char **argv, secgw_command_args_t *command_args)
{
	struct option lgopts[] = {
		{"help", 0, 0, 'H'},
		{"enable-graph-stats", 0, 0, 'g'},
	};
	int i_present, p_present, s_present;
	char *app_name = argv[0];
	int opt, option_index;

	/* Parse args */
	i_present = 0;
	p_present = 0;
	s_present = 0;

	while ((opt = getopt_long(argc, argv, "i:p:s:", lgopts, &option_index)) != EOF) {
		switch (opt) {
		case 'i':
			if (i_present) {
				dao_err("Error: Multiple -i arguments");
				return -1;
			}
			i_present = 1;

			if (!strlen(optarg)) {
				dao_err("Error: Argument for -i not provided");
				return -1;
			}

			command_args->cli_conn_param.addr = strdup(optarg);
			if (command_args->cli_conn_param.addr == NULL) {
				dao_err("Error: Not enough memory");
				return -1;
			}
			break;

		case 'p':
			if (p_present) {
				dao_err("Error: Multiple -p arguments");
				return -1;
			}
			p_present = 1;

			if (!strlen(optarg)) {
				dao_err("Error: Argument for -p not provided");
				return -1;
			}

			command_args->cli_conn_param.port = (uint16_t)strtoul(optarg, NULL, 10);
		break;

		case 's':
			if (s_present) {
				dao_err("Error: Multiple -s arguments");
				return -1;
			}
			s_present = 1;

			if (!strlen(optarg)) {
				dao_err("Error: Argument for -s not provided");
				return -1;
			}

			command_args->cli_script_file_name = strdup(optarg);
			if (command_args->cli_script_file_name == NULL) {
				dao_err("Error: Not enough memory for script file name");
				return -1;
			}
			break;

		case 'g':
			command_args->enable_graph_stats = true;
			dao_warn("WARNING! Telnet session can not be accessed with"
				 "--enable-graph-stats");
			break;

		case 'H':
		default:
			printf(usage, app_name);
			return -1;
		}
	}
	optind = 1; /* reset getopt lib */

	return 0;
}

int main(int argc, char **argv)
{
	secgw_numa_id_t *numa = NULL;
	struct scli_conn_params *cparams = NULL;
	secgw_worker_t *sgw = NULL;
	secgw_main_t *sm = NULL;
	char name[256];
	int rc;

	rc = secgw_main_init(argc, argv, sizeof(secgw_worker_t));
	if (rc < 0)
		DAO_ERR_GOTO(rc, _error, "rte_eal_init_failed: %s", argv[0]);

	argc -= rc;
	argv += rc;

	if (initialize_command_line_args())
		return -1;

	if (parse_command_line_args(argc, argv, secgw_command_args))
		return -1;

	if (dao_workers_num_workers_get() < 1) {
		dao_err("Launch app on more cores, found %d workers",
			dao_workers_num_workers_get());
		return -1;
	}

	sm = secgw_get_main();

	if (dao_workers_app_data_get(dao_workers_self_worker_get(), (void **)&sgw, NULL))
		DAO_ERR_GOTO(rc, _error, "app_data_get failed: %s", argv[0]);

	if (!sgw)
		return -1;

	sgw->cli_conn = NULL;
	if (secgw_command_args->cli_script_file_name) {
		scli_init();
		cparams = &secgw_command_args->cli_conn_param;
		cparams->msg_handle_arg = NULL;

		sgw->cli_conn = scli_conn_init(cparams);
		if (!sgw->cli_conn)
			DAO_ERR_GOTO(rc, _error, "sli_conn_init() failed: %s", argv[0]);

		if (scli_script_process(secgw_command_args->cli_script_file_name,
					cparams->msg_in_len_max,
					cparams->msg_out_len_max, NULL)) {
			DAO_ERR_GOTO(rc, error, "cli_script_process() failed: %s", argv[0]);
		}
		secgw_info("CLI configured %s:%u", cparams->addr, cparams->port);
	}
	signal(SIGINT, secgw_signal_handler);
	signal(SIGTERM, secgw_signal_handler);

	/* Create Mempool for each socket/numa id */
	STAILQ_FOREACH(numa, &sm->secgw_main_numa_list, next_numa_id) {
		snprintf(name, sizeof(name), "%s-%s-%d", "mempool", "numa", numa->numa_id);

		numa->user_arg = NULL;
		numa->user_arg = (void *)rte_pktmbuf_pool_create(
			name, SECGW_MEMPOOL_NUM_MBUFS, SECGW_MEMPOOL_CACHE_SIZE,
			RTE_CACHE_LINE_SIZE, RTE_MBUF_DEFAULT_BUF_SIZE, numa->numa_id);

		if (!numa->user_arg)
			DAO_ERR_GOTO(ENOMEM, error, "rte_mempool fails for %s", name);

		secgw_dbg("Created packet mempool: %s", name);
	}

	if (register_devices() <= 0)
		DAO_ERR_GOTO(EINVAL, error, "No device found in secgw_register_ethdevs()");

	pair_tap_to_ethdev();

	/* Connect next node edges from interface-outout node to all active tx-nodes */
	connect_interface_output_next_nodes();

	start_devices();

	if (dao_netlink_xfrm_notifier_register(&secgw_xfrm_ops, NULL) < 0)
		DAO_ERR_GOTO(EINVAL, error, "dao xfrm netlink register failed");

	if (dao_netlink_route_notifier_register(&secgw_route_ops, SECGW_TAP_PORT_GROUP_NAME) < 0)
		DAO_ERR_GOTO(EINVAL, error, "dao route table notifier failed");

	if (enable_feature_arc())
		DAO_ERR_GOTO(EINVAL, error, "feature_arc enabling failed");

	dao_dbg("Launching threads");
	sm = secgw_get_main();

	rte_eal_mp_remote_launch(secgw_thread_cb, sm, CALL_MAIN);

	return 0;

error:
	if (sgw && sgw->cli_conn)
		scli_conn_free(sgw->cli_conn);
	if (secgw_command_args->cli_script_file_name)
		scli_exit();
_error:
	secgw_main_exit();
	return rc;
}
