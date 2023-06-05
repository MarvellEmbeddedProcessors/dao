/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <dao_netlink.h>
#include <dao_dynamic_string.h>

#include <netlink/socket.h>
#include <netlink/xfrm/sa.h>
#include <netlink/xfrm/sp.h>
#include <netlink/xfrm/ae.h>
#include <netlink/xfrm/template.h>
#include <netlink/xfrm/selector.h>
#include <netlink/xfrm/lifetime.h>

#define ELIB_SOCK_SZ (4 * 1024 * 1024)

/**
 * A Netlink notifier object
 */
typedef struct dao_netlink_notifier {
	STAILQ_ENTRY(dao_netlink_notifier) next_notifier;

	void *dao_netlink; /*< back pointer to netlink */

	/** application specific ops */
	void *app_callback_ops;

	/** parse_cb() to be called */
	dao_netlink_parse_cb_t parse_cb;

	/** cookie set by application */
	void *app_cookie;

	/** received msg which parse_cb sets */
	void *msg;

	/** variable tracking number of multicast_groups subscribed */
	uint16_t n_multicast_groups;

	/** multicast groups that this notifier has subscribed to */
	uint64_t multicast_groups[DAO_NETLINK_NOTIFIER_MAX_MULTICAST_GROUPS];
} dao_netlink_notifier_t;

/**
 * A netlink object
 */
typedef struct dao_netlink {
	struct nl_sock *sock;

	int protocol;

	int fd;

	int has_poll_recv;

	STAILQ_HEAD(, dao_netlink_notifier) all_notifiers;

	STAILQ_ENTRY(dao_netlink) next_netlink;
} dao_netlink_t;

typedef STAILQ_HEAD(, dao_netlink) netlinks_head_t;

/* Global list holding dao_netlink_t */
static netlinks_head_t netlinks_head = STAILQ_HEAD_INITIALIZER(netlinks_head);

static int netlink_parse_cb(struct nl_msg *msg, void *arg)
{
	dao_netlink_notifier_t *notifier = (struct dao_netlink_notifier *)arg;
	dao_netlink_t *en = notifier->dao_netlink;
	struct  nlmsghdr *hdr;
	int err;

	nlmsg_get(msg);
	hdr = nlmsg_hdr(msg);

	dao_dbg("nlmsg_len: %u, type: %u, flags: 0x%x, seq: %u, pid: %u",
		hdr->nlmsg_len, hdr->nlmsg_type, hdr->nlmsg_flags, hdr->nlmsg_seq,
		hdr->nlmsg_pid);

	en->has_poll_recv = 1;

	/* Save msg in notifier */
	if (notifier)
		notifier->msg = (void *)msg;

	switch (en->protocol) {
	case NETLINK_XFRM:
	case NETLINK_ROUTE:
		err = nl_msg_parse(msg, notifier->parse_cb, notifier);
	break;

	default:
		dao_err("Invalid notifier protocol: %d", en->protocol);
		return -1;
	}

	/* Reset msg now */
	if (notifier)
		notifier->msg = NULL;

	if (err < 0) {
		dao_err("nl_msg_parse failed: %s", nl_geterror(err));
		nlmsg_free(msg);
		return -1;
	}
	dao_dbg("netlink message processed successfully");
	nlmsg_free(msg);
	return 0;
}

static inline dao_netlink_t *
__dao_netlink_lookup(int protocol)
{
	struct dao_netlink *entry = NULL;

	STAILQ_FOREACH(entry, &netlinks_head, next_netlink) {
		if (entry->protocol == protocol)
			return entry;
	}
	return NULL;
}

static struct dao_netlink_notifier *
__dao_netlink_notifier_lookup_by_parse_cb(void *netlink, dao_netlink_parse_cb_t parse_cb)
{
	dao_netlink_t *en = (dao_netlink_t *)netlink;
	struct dao_netlink_notifier *entry = NULL;

	STAILQ_FOREACH(entry, &en->all_notifiers, next_notifier) {
		RTE_VERIFY(entry->dao_netlink == en);
		if (parse_cb)
			if (entry->parse_cb == parse_cb)
				return entry;
	}
	return NULL;
}

void*
dao_netlink_lookup(int protocol)
{
	return ((void *)__dao_netlink_lookup(protocol));
}

int dao_netlink_has_poll_recv(void *netlink)
{
	struct dao_netlink *entry = (struct dao_netlink *)netlink;

	return entry->has_poll_recv;
}

void *dao_netlink_socket_get(void *netlink)
{
	struct dao_netlink *entry = (struct dao_netlink *)netlink;

	return ((void *)entry->sock);
}

int dao_netlink_fd_get(void *netlink)
{
	struct dao_netlink *entry = (struct dao_netlink *)netlink;

	return entry->fd;
}

void *
dao_netlink_notifier_lookup_by_parse_cb(void *netlink, dao_netlink_parse_cb_t parse_cb)
{
	return ((void *)__dao_netlink_notifier_lookup_by_parse_cb(netlink, parse_cb));
}

void *
dao_netlink_notifier_lookup_by_multicast_group(void *netlink, dao_netlink_parse_cb_t parse_cb,
					       uint32_t multicast_group)
{
	dao_netlink_t *en = (dao_netlink_t *)netlink;
	struct dao_netlink_notifier *entry = NULL;
	int iter = 0;

	STAILQ_FOREACH(entry, &en->all_notifiers, next_notifier) {
		RTE_VERIFY(entry->dao_netlink == en);
		/*
		 * Caller can pass NULL as parse_cb to get first netlink_notifier
		 * that matches multicast_group
		 */
		for (iter = 0; iter < entry->n_multicast_groups; iter++) {
			if (parse_cb) {
				if ((entry->multicast_groups[iter] == multicast_group) &&
				    (entry->parse_cb == parse_cb))
					return entry;
			} else {
				if (entry->multicast_groups[iter] == multicast_group)
					return entry;
			}
		}
	}
	return NULL;
}

void *dao_netlink_notifier_callback_ops_get(void *netlink_notifier)
{
	dao_netlink_notifier_t *notifier = (dao_netlink_notifier_t *)netlink_notifier;

	return notifier->app_callback_ops;
}

void *dao_netlink_notifier_app_cookie_get(void *netlink_notifier)
{
	dao_netlink_notifier_t *notifier = (dao_netlink_notifier_t *)netlink_notifier;

	return notifier->app_cookie;
}

void *dao_netlink_notifier_nl_msg_get(void *netlink_notifier)
{
	dao_netlink_notifier_t *notifier = (dao_netlink_notifier_t *)netlink_notifier;

	return notifier->msg;
}

int dao_netlink_register(int protocol, dao_netlink_parse_cb_t parse_cb,
			 void *ops, void *aux, ...)
{
	uint32_t mc_groups[DAO_NETLINK_NOTIFIER_MAX_MULTICAST_GROUPS] = {0};
	dao_netlink_notifier_t *enln = NULL, *temp = NULL;
	struct dao_ds s = DS_EMPTY_INITIALIZER;
	int iter, n_mc_group = 0, j;
	dao_netlink_t *en = NULL;
	uint32_t temp_group = 0;
	uint64_t mask = 0;
	va_list arg_ptr;
	int is_unique;

	en = __dao_netlink_lookup(protocol);
	if (!en) {
		en = malloc(sizeof(dao_netlink_t));
		if (!en) {
			dao_err("emalloc failed");
			return -1;
		}

		memset(en, 0, sizeof(dao_netlink_t));

		/* Initialized newly allocated  */
		en->fd = -1;
		en->protocol = protocol;
		STAILQ_INIT(&en->all_notifiers);
	}

	memset(mc_groups, 0, sizeof(mc_groups[0]) *
					DAO_NETLINK_NOTIFIER_MAX_MULTICAST_GROUPS);

	va_start(arg_ptr, aux);

	while ((temp_group = va_arg(arg_ptr, uint32_t)))
		mc_groups[n_mc_group++] = temp_group;

	/* First time initialization */
	if (en->fd < 0) {
		en->sock = nl_socket_alloc();

		if (!en->sock)
			DAO_ERR_GOTO(-ENOENT, free_netlink, "nl_socket_alloc failed");

		nl_socket_disable_seq_check(en->sock);

		/**
		 * For XFRM only nl_join_groups seems to work
		 */
		if (protocol == NETLINK_XFRM) {
			mask = 0;
			for (iter = 0; iter < n_mc_group; iter++)
				mask |= mc_groups[iter];

			nl_join_groups(en->sock, mask);
		}

		if (nl_connect(en->sock, protocol) < 0)
			DAO_ERR_GOTO(-EPROTOTYPE, close_socket,
				     "nl_connect failed for protocol: %d",
				     protocol);

		en->fd = nl_socket_get_fd(en->sock);

		if (en->fd < 0)
			DAO_ERR_GOTO(-EBADF, close_socket, "Invalid fd: %d", en->fd);

		if (nl_socket_set_nonblocking(en->sock))
			DAO_ERR_GOTO(-EAGAIN, close_socket, "Unable to set nonblocking socket");

		if (nl_socket_set_buffer_size(en->sock, ELIB_SOCK_SZ, ELIB_SOCK_SZ))
			DAO_ERR_GOTO(-EFBIG, close_socket, "Unable to set buffer size");

		if (protocol != NETLINK_XFRM) {
			for (iter = 0; iter < n_mc_group; iter++) {
				temp_group = mc_groups[iter];
				if (nl_socket_add_membership(en->sock, temp_group)) {
					dao_err("membership: %u fails for protocol: %d",
						temp_group, en->protocol);
					dao_netlink_close(en);
					return -EAGAIN;
				}
				dao_dbg("NL_Proto %d(fd %d): Multicast group: %u added",
					protocol, en->fd, temp_group);
			}
		}
		STAILQ_INSERT_TAIL(&netlinks_head, en, next_netlink);
	} else {
		dao_dbg("appending membership of new multicast groups");
		for (iter = 0; iter < n_mc_group; iter++) {
			temp_group = mc_groups[iter];
			/* If multicast group is duplicate. skip adding membership */
			enln =
			dao_netlink_notifier_lookup_by_multicast_group(en,
								       NULL,
								       temp_group);
			if (enln)
				continue;

			if (protocol != NETLINK_XFRM) {
				if (nl_socket_add_membership(en->sock, temp_group)) {
					dao_err("group: %u fails for protocol: %d",
						temp_group, en->protocol);
					//dao_netlink_close(en);
					return -EAGAIN;
				}
				/* We have to save multicast groups to valid
				 * notifier->multicast_groups only when we can
				 * allocate one. Hence we do it below
				 */
			} else {
				dao_err("Adding multicast groups for NETLINK_XFRM supported only once");
				return -EOPNOTSUPP;
			}
		}
	}

	/* Add notifier first time */
	enln = __dao_netlink_notifier_lookup_by_parse_cb(en, parse_cb);
	if (!enln && (en->fd >= 0)) {
		/* Allocate netlink notifier */
		enln = malloc(sizeof(dao_netlink_notifier_t));
		if (!enln)
			DAO_ERR_GOTO(-ENOMEM, close_socket, "malloc failed for allocating notifier");

		memset(enln, 0, sizeof(dao_netlink_notifier_t));
		enln->n_multicast_groups = n_mc_group;

		for (iter = 0; iter < n_mc_group; iter++) {
			is_unique = 1;
			for (j = 0; j < iter; j++) {
				if (mc_groups[j] == mc_groups[iter])
					is_unique = 0;
			}
			if (is_unique) {
				enln->multicast_groups[iter] = mc_groups[iter];
				dao_ds_put_format(&s, "%u, ", enln->multicast_groups[iter]);
			}
		}

		RTE_VERIFY(enln->n_multicast_groups <= DAO_NETLINK_NOTIFIER_MAX_MULTICAST_GROUPS);

		enln->app_callback_ops = ops;
		enln->app_cookie = aux;
		enln->dao_netlink = en;
		enln->parse_cb = parse_cb;

		if (nl_socket_modify_cb(en->sock, NL_CB_VALID, NL_CB_CUSTOM,
					netlink_parse_cb, enln))
			DAO_ERR_GOTO(-EOPNOTSUPP, free_notifier, "nl_socket_modify_cb() fails");

		/* Add to the list */
		STAILQ_INSERT_TAIL(&en->all_notifiers, enln, next_notifier);
	} else {
		dao_dbg("saving new multicast groups in notifier array");

		/* fd cannot be invalid */
		if (en->fd < 0)
			RTE_VERIFY(0);

		for (iter = enln->n_multicast_groups; iter < n_mc_group; iter++) {
			/* If multicast group is already registered. skip it */
			temp =
			dao_netlink_notifier_lookup_by_multicast_group(en,
								       NULL,
								       temp_group);
			if (temp)
				continue;

			enln->multicast_groups[enln->n_multicast_groups++] = temp_group;
			dao_ds_put_format(&s, "%u, ", enln->multicast_groups[iter]);
		}
		RTE_VERIFY(enln->n_multicast_groups <=
			   DAO_NETLINK_NOTIFIER_MAX_MULTICAST_GROUPS);
	}
	if (n_mc_group) {
		dao_info("Protocol: %d, fd: %d, Multicast_Groups: %s",
			 en->protocol, en->fd, dao_ds_cstr(&s));
		dao_ds_destroy(&s);
	}
	return 0;

free_notifier:
	if (enln)
		free(enln);
close_socket:
	if (en && en->sock)
		nl_socket_free(en->sock);
free_netlink:
	if (en)
		free(en);

	return -1;
}

int dao_netlink_close(void *netlink)
{
	struct dao_netlink *entry = (struct dao_netlink *)netlink;
	struct dao_netlink_notifier *notifier = NULL;

	if (!entry)
		return -1;

	while (!STAILQ_EMPTY(&entry->all_notifiers)) {
		notifier = STAILQ_FIRST(&entry->all_notifiers);
		STAILQ_REMOVE_HEAD(&entry->all_notifiers, next_notifier);
		free(notifier);
	}
	if (entry->sock)
		nl_socket_free(entry->sock);
	free(entry);

	return 0;
}

int dao_netlink_cleanup(void)
{
	struct dao_netlink *entry = NULL;

	while (!STAILQ_EMPTY(&netlinks_head)) {
		entry = STAILQ_FIRST(&netlinks_head);
		STAILQ_REMOVE_HEAD(&netlinks_head, next_netlink);
		dao_netlink_close((void *)entry);
	}

	return 0;
}

int dao_netlink_poll(void)
{
	struct dao_netlink *entry = NULL;
	int err = -1;

	STAILQ_FOREACH(entry, &netlinks_head, next_netlink) {
		if (entry && !entry->has_poll_recv && entry->sock) {
			while ((err = nl_recvmsgs_default(entry->sock)) > -1)
				;
			if (err != -NLE_AGAIN)
				dao_err("Error(%d) with nl_recvmsgs_default()", err);
		}
	}
	return err;
}

int dao_netlink_poll_complete(void)
{
	struct dao_netlink *entry = NULL;

	STAILQ_FOREACH(entry, &netlinks_head, next_netlink)
		if (entry && entry->sock && (entry->fd > -1))
			entry->has_poll_recv = 0;

	/* Call any high level netlink APIs periodic updates */
	/* dao_netlink_route_notifier_run(); */

	return 0;
}

int
dao_netlink_nl_addr_to_in6(struct in6_addr *ip_addr, struct nl_addr *nladdr)
{
	rte_be32_t ip4;

	switch (nl_addr_get_family(nladdr)) {
	case AF_INET6:
		memcpy(ip_addr, nl_addr_get_binary_addr(nladdr), sizeof(*ip_addr));
	break;

	case AF_INET:
		ip4 = *(rte_be32_t *)nl_addr_get_binary_addr(nladdr);
		dao_in6_addr_set_mapped_ipv4(ip_addr, ip4);
		return 0;
	default:
	}
	return -1;
}
