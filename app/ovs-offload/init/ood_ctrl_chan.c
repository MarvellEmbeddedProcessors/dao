/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <rte_malloc.h>

#include <dao_log.h>

#include <ood_init.h>
#include <ood_msg_ctrl.h>

static void
close_socket(int fd)
{
	close(fd);
}

int
ood_ctrl_msg_recv(int socketfd, void *data, uint32_t len)
{
	struct msghdr mh = { 0 };
	struct iovec iov[1];
	ssize_t size;
	int afd = -1;
	struct cmsghdr *cmsg;
	static uint64_t rec;

	if (socketfd < 0) {
		dao_err("Invalid socket fd");
		return 0;
	}
	iov[0].iov_base = data;
	iov[0].iov_len = len;
	mh.msg_iov = iov;
	mh.msg_iovlen = 1;
	mh.msg_control = NULL;
	mh.msg_controllen = 0;

	size = recvmsg(socketfd, &mh, MSG_DONTWAIT);
	if (size < 0) {
		if (errno == EAGAIN)
			return 0;
		dao_err("recvmsg err %d", errno);
		return -errno;
	} else if (size == 0) {
		return size;
	}

	cmsg = CMSG_FIRSTHDR(&mh);
	while (cmsg) {
		if (cmsg->cmsg_level == SOL_SOCKET) {
			if (cmsg->cmsg_type == SCM_RIGHTS) {
				rte_memcpy(&afd, CMSG_DATA(cmsg), sizeof(int));
				printf("afd %d", afd);
			}
		}
		cmsg = CMSG_NXTHDR(&mh, cmsg);
	}

	rec++;
	dao_dbg("Packet %ld Received %ld bytes", rec, size);

	return size;
}

ssize_t
ood_ctrl_msg_send(int socketfd, void *data, uint32_t len, int afd)
{
	struct msghdr mh = {0};
	struct iovec iov[1];
	struct cmsghdr *cmsg;
	char ctl[CMSG_SPACE(sizeof(int))];
	ssize_t size;
	static uint64_t sent;

	if (socketfd < 0) {
		dao_err("Invalid socket fd");
		return 0;
	}

	iov[0].iov_base = data;
	iov[0].iov_len = len;
	mh.msg_iov = iov;
	mh.msg_iovlen = 1;

	if (afd > 0) {
		memset(&ctl, 0, sizeof(ctl));
		mh.msg_control = ctl;
		mh.msg_controllen = sizeof(ctl);
		cmsg = CMSG_FIRSTHDR(&mh);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		rte_memcpy(CMSG_DATA(cmsg), &afd, sizeof(int));
	}

	size =  sendmsg(socketfd, &mh, MSG_DONTWAIT);
	if (size < 0) {
		if (errno == EAGAIN)
			return 0;
		dao_err("Failed to send message, err %d", -errno);
		return -errno;
	} else if (size == 0) {
		return 0;
	}

	sent++;
	dao_dbg("Packet %ld Sent %ld bytes on socketfd %d", sent, size, socketfd);

	return size;
}

static void
poll_for_control_msg(struct ood_main_cfg_data *ood_main_cfg)
{
	uint32_t len = BUFSIZ;
	int sz = 0;
	void *msg_buf;

	msg_buf = rte_zmalloc("Ctrl_msg", len, 0);
	while (sz == 0 && !ood_main_cfg->force_quit) {
		sz = ood_ctrl_msg_recv(ood_main_cfg->ctrl_chan_prm->sock_fd, msg_buf, len);
		if (sz != 0)
			break;
	}
	if (sz > 0) {
		dao_dbg("Received new %d bytes control message", sz);
		rte_spinlock_lock(&ood_main_cfg->ctrl_chan_prm->ctrl_chan_lock);
		ood_process_control_packet(msg_buf, sz);
		/* Freeing the allocated buffer */
		rte_free(msg_buf);
		rte_spinlock_unlock(&ood_main_cfg->ctrl_chan_prm->ctrl_chan_lock);
	}
}

static uint32_t
ctrl_chan_thread(void *arg)
{
	struct ood_main_cfg_data *ood_main_cfg = (struct ood_main_cfg_data *)arg;

	while (!ood_main_cfg->force_quit) {
		if (ood_main_cfg->ctrl_chan_prm->ctrl_msg_polling_enabled)
			poll_for_control_msg(ood_main_cfg);
	}

	/* Closing the opened socket */
	close_socket(ood_main_cfg->ctrl_chan_prm->sock_fd);

	dao_dbg("Exiting representor ctrl thread");

	return 0;
}

static int
connect_to_server(void)
{
	struct sockaddr_un remote;
	int sock_fd, len;
	int flags;

	sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		dao_err("failed to create unix socket");
		return -1;
	}

	flags = fcntl(sock_fd, F_GETFL, 0);
	fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK);

	/* Set unix socket path and bind */
	memset(&remote, 0, sizeof(remote));
	remote.sun_family = AF_UNIX;

	if (strlen(OOD_CTRL_CHAN_SRV_SOCK) > sizeof(remote.sun_path) - 1) {
		dao_err("Server socket path too long: %s", OOD_CTRL_CHAN_SRV_SOCK);
		close(sock_fd);
		return -E2BIG;
	}

	memset(&remote, 0, sizeof(remote));

	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, OOD_CTRL_CHAN_SRV_SOCK);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);

	if (connect(sock_fd, (struct sockaddr *)&remote, len) == -1) {
		dao_err("remove-%s", OOD_CTRL_CHAN_SRV_SOCK);
		close(sock_fd);
		return -errno;
	}

	return sock_fd;
}

static int
ood_ctrl_chan_setup(struct ood_main_cfg_data *ood_main_cfg)
{
	rte_thread_t thread;
	int rc, sock_fd;

	sock_fd = connect_to_server();
	if (sock_fd < 0) {
		dao_err("Failed to open socket, err %d", sock_fd);
		return -1;
	}

	/* Synchronization between packet received from server and processing
	 * response packets for client requests.
	 */
	rte_spinlock_init(&ood_main_cfg->ctrl_chan_prm->ctrl_chan_lock);
	ood_main_cfg->ctrl_chan_prm->sock_fd = sock_fd;

	/* Create a thread for handling control messages */
	rc = rte_thread_create_control(&thread, "ctrl-chan-thrd", ctrl_chan_thread,
				       ood_main_cfg);
	if (rc != 0)
		DAO_ERR_GOTO(rc, fail, "Failed to create thread for VF mbox handling");

	/* Save the thread handle to join later */
	ood_main_cfg->ctrl_chan_prm->ctrl_chan_thrd = thread;

	return 0;
fail:
	return errno;
}

representor_mapping_t *
ood_representor_mapping_get(uint16_t repr_qid)
{
	const struct rte_memzone *mz;
	struct ood_main_cfg_data *ood_main_cfg;
	ood_repr_param_t *repr_prm;
	int i;

	mz = rte_memzone_lookup(OOD_MAIN_CFG_MZ_NAME);
	if (!mz) {
		dao_err("Failed to lookup for main_cfg, err %d", rte_errno);
		return NULL;
	}
	ood_main_cfg = mz->addr;
	repr_prm = ood_main_cfg->repr_prm;

	for (i = 0; i < repr_prm->nb_repr; i++) {
		if (repr_prm->repr_map[i] == repr_qid)
			break;
	}

	if (i == repr_prm->nb_repr)
		return NULL;
	else
		return &ood_main_cfg->ctrl_chan_prm->rep_map[i];
}

int
ood_control_channel_init(struct ood_main_cfg_data *ood_main_cfg)
{
	representor_mapping_t *rep_map;
	uint16_t repr_qid;
	ood_repr_param_t *repr_prm;
	ood_ethdev_param_t *eth_prm;
	ood_config_param_t *cfg_prm;
	struct ood_ethdev_host_mac_map *host_mac_lkp_tbl;
	int i, nb_port;

	eth_prm = ood_main_cfg->eth_prm;
	cfg_prm = ood_main_cfg->cfg_prm;
	repr_prm = ood_main_cfg->repr_prm;

	rep_map = ood_main_cfg->ctrl_chan_prm->rep_map;
	host_mac_lkp_tbl = eth_prm->host_mac_map;
	nb_port = cfg_prm->nb_port_pair_params;

	for (i = 0; i < nb_port; i++) {
		repr_qid = i;
		rep_map[repr_qid].host_port = host_mac_lkp_tbl[i].host_port;
		rep_map[repr_qid].mac_port = host_mac_lkp_tbl[i].mac_port;
		/* Linked list for storing host and mac ports */
		STAILQ_INIT(&rep_map[repr_qid].flow_list);
	}

	ood_ctrl_chan_setup(ood_main_cfg);

	/* Sending ready message */
	ood_send_ready_message();
	for (i = 0; i < repr_prm->nb_repr; i++)
		dao_dbg("Representor Port %d rapid %d mac port %d host port %d", i,
			repr_prm->repr_map[i], rep_map[i].mac_port, rep_map[i].host_port);

	return 0;
}
