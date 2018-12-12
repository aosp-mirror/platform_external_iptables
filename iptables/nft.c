/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <errno.h>
#include <netdb.h>	/* getprotobynumber */
#include <time.h>
#include <stdarg.h>
#include <inttypes.h>
#include <assert.h>

#include <xtables.h>
#include <libiptc/libxtc.h>
#include <libiptc/xtcshared.h>

#include <stdlib.h>
#include <string.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <netinet/ip6.h>

#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_tables_compat.h>

#include <linux/netfilter/xt_limit.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/set.h>
#include <libnftnl/udata.h>
#include <libnftnl/batch.h>

#include <netinet/in.h>	/* inet_ntoa */
#include <arpa/inet.h>

#include "nft.h"
#include "xshared.h" /* proto_to_name */
#include "nft-shared.h"
#include "xtables-config-parser.h"

static void *nft_fn;

int mnl_talk(struct nft_handle *h, struct nlmsghdr *nlh,
	     int (*cb)(const struct nlmsghdr *nlh, void *data),
	     void *data)
{
	int ret;
	char buf[16536];

	if (mnl_socket_sendto(h->nl, nlh, nlh->nlmsg_len) < 0)
		return -1;

	ret = mnl_socket_recvfrom(h->nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, h->seq, h->portid, cb, data);
		if (ret <= 0)
			break;

		ret = mnl_socket_recvfrom(h->nl, buf, sizeof(buf));
	}
	if (ret == -1) {
		return -1;
	}

	return 0;
}

#define NFT_NLMSG_MAXSIZE (UINT16_MAX + getpagesize())

/* selected batch page is 256 Kbytes long to load ruleset of
 * half a million rules without hitting -EMSGSIZE due to large
 * iovec.
 */
#define BATCH_PAGE_SIZE getpagesize() * 32

static struct nftnl_batch *mnl_batch_init(void)
{
	struct nftnl_batch *batch;

	batch = nftnl_batch_alloc(BATCH_PAGE_SIZE, NFT_NLMSG_MAXSIZE);
	if (batch == NULL)
		return NULL;

	return batch;
}

static void mnl_nft_batch_continue(struct nftnl_batch *batch)
{
	assert(nftnl_batch_update(batch) >= 0);
}

static uint32_t mnl_batch_begin(struct nftnl_batch *batch, uint32_t seqnum)
{
	nftnl_batch_begin(nftnl_batch_buffer(batch), seqnum);
	mnl_nft_batch_continue(batch);

	return seqnum;
}

static void mnl_batch_end(struct nftnl_batch *batch, uint32_t seqnum)
{
	nftnl_batch_end(nftnl_batch_buffer(batch), seqnum);
	mnl_nft_batch_continue(batch);
}

static void mnl_batch_reset(struct nftnl_batch *batch)
{
	nftnl_batch_free(batch);
}

struct mnl_err {
	struct list_head	head;
	int			err;
	uint32_t		seqnum;
};

static void mnl_err_list_node_add(struct list_head *err_list, int error,
				  int seqnum)
{
	struct mnl_err *err = malloc(sizeof(struct mnl_err));

	err->seqnum = seqnum;
	err->err = error;
	list_add_tail(&err->head, err_list);
}

static void mnl_err_list_free(struct mnl_err *err)
{
	list_del(&err->head);
	free(err);
}

static int nlbuffsiz;

static void mnl_set_sndbuffer(const struct mnl_socket *nl,
			      struct nftnl_batch *batch)
{
	int newbuffsiz;

	if (nftnl_batch_iovec_len(batch) * BATCH_PAGE_SIZE <= nlbuffsiz)
		return;

	newbuffsiz = nftnl_batch_iovec_len(batch) * BATCH_PAGE_SIZE;

	/* Rise sender buffer length to avoid hitting -EMSGSIZE */
	if (setsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_SNDBUFFORCE,
		       &newbuffsiz, sizeof(socklen_t)) < 0)
		return;

	nlbuffsiz = newbuffsiz;
}

static ssize_t mnl_nft_socket_sendmsg(const struct mnl_socket *nf_sock,
				      struct nftnl_batch *batch)
{
	static const struct sockaddr_nl snl = {
		.nl_family = AF_NETLINK
	};
	uint32_t iov_len = nftnl_batch_iovec_len(batch);
	struct iovec iov[iov_len];
	struct msghdr msg = {
		.msg_name	= (struct sockaddr *) &snl,
		.msg_namelen	= sizeof(snl),
		.msg_iov	= iov,
		.msg_iovlen	= iov_len,
	};

	mnl_set_sndbuffer(nf_sock, batch);
	nftnl_batch_iovec(batch, iov, iov_len);

	return sendmsg(mnl_socket_get_fd(nf_sock), &msg, 0);
}

static int mnl_batch_talk(const struct mnl_socket *nf_sock,
			  struct nftnl_batch *batch, struct list_head *err_list)
{
	const struct mnl_socket *nl = nf_sock;
	int ret, fd = mnl_socket_get_fd(nl), portid = mnl_socket_get_portid(nl);
	char rcv_buf[MNL_SOCKET_BUFFER_SIZE];
	fd_set readfds;
	struct timeval tv = {
		.tv_sec		= 0,
		.tv_usec	= 0
	};
	int err = 0;

	ret = mnl_nft_socket_sendmsg(nf_sock, batch);
	if (ret == -1)
		return -1;

	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);

	/* receive and digest all the acknowledgments from the kernel. */
	ret = select(fd+1, &readfds, NULL, NULL, &tv);
	if (ret == -1)
		return -1;

	while (ret > 0 && FD_ISSET(fd, &readfds)) {
		struct nlmsghdr *nlh = (struct nlmsghdr *)rcv_buf;

		ret = mnl_socket_recvfrom(nl, rcv_buf, sizeof(rcv_buf));
		if (ret == -1)
			return -1;

		ret = mnl_cb_run(rcv_buf, ret, 0, portid, NULL, NULL);
		/* Continue on error, make sure we get all acknowledgments */
		if (ret == -1) {
			mnl_err_list_node_add(err_list, errno, nlh->nlmsg_seq);
			err = -1;
		}

		ret = select(fd+1, &readfds, NULL, NULL, &tv);
		if (ret == -1)
			return -1;

		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
	}
	return err;
}

enum obj_update_type {
	NFT_COMPAT_TABLE_ADD,
	NFT_COMPAT_TABLE_FLUSH,
	NFT_COMPAT_CHAIN_ADD,
	NFT_COMPAT_CHAIN_USER_ADD,
	NFT_COMPAT_CHAIN_USER_DEL,
	NFT_COMPAT_CHAIN_USER_FLUSH,
	NFT_COMPAT_CHAIN_UPDATE,
	NFT_COMPAT_CHAIN_RENAME,
	NFT_COMPAT_CHAIN_ZERO,
	NFT_COMPAT_RULE_APPEND,
	NFT_COMPAT_RULE_INSERT,
	NFT_COMPAT_RULE_REPLACE,
	NFT_COMPAT_RULE_DELETE,
	NFT_COMPAT_RULE_FLUSH,
};

enum obj_action {
	NFT_COMPAT_COMMIT,
	NFT_COMPAT_ABORT,
};

struct obj_update {
	struct list_head	head;
	enum obj_update_type	type;
	unsigned int		seq;
	union {
		struct nftnl_table	*table;
		struct nftnl_chain	*chain;
		struct nftnl_rule	*rule;
		void			*ptr;
	};
	struct {
		unsigned int		lineno;
	} error;
};

static int mnl_append_error(const struct nft_handle *h,
			    const struct obj_update *o,
			    const struct mnl_err *err,
			    char *buf, unsigned int len)
{
	static const char *type_name[] = {
		[NFT_COMPAT_TABLE_ADD] = "TABLE_ADD",
		[NFT_COMPAT_TABLE_FLUSH] = "TABLE_FLUSH",
		[NFT_COMPAT_CHAIN_ADD] = "CHAIN_ADD",
		[NFT_COMPAT_CHAIN_USER_ADD] = "CHAIN_USER_ADD",
		[NFT_COMPAT_CHAIN_USER_DEL] = "CHAIN_USER_DEL",
		[NFT_COMPAT_CHAIN_USER_FLUSH] = "CHAIN_USER_FLUSH",
		[NFT_COMPAT_CHAIN_UPDATE] = "CHAIN_UPDATE",
		[NFT_COMPAT_CHAIN_RENAME] = "CHAIN_RENAME",
		[NFT_COMPAT_CHAIN_ZERO] = "CHAIN_ZERO",
		[NFT_COMPAT_RULE_APPEND] = "RULE_APPEND",
		[NFT_COMPAT_RULE_INSERT] = "RULE_INSERT",
		[NFT_COMPAT_RULE_REPLACE] = "RULE_REPLACE",
		[NFT_COMPAT_RULE_DELETE] = "RULE_DELETE",
		[NFT_COMPAT_RULE_FLUSH] = "RULE_FLUSH",
	};
	char errmsg[256];
	char tcr[128];

	if (o->error.lineno)
		snprintf(errmsg, sizeof(errmsg), "\nline %u: %s failed (%s)",
			 o->error.lineno, type_name[o->type], strerror(err->err));
	else
		snprintf(errmsg, sizeof(errmsg), " %s failed (%s)",
			 type_name[o->type], strerror(err->err));

	switch (o->type) {
	case NFT_COMPAT_TABLE_ADD:
	case NFT_COMPAT_TABLE_FLUSH:
		snprintf(tcr, sizeof(tcr), "table %s",
			 nftnl_table_get_str(o->table, NFTNL_TABLE_NAME));
		break;
	case NFT_COMPAT_CHAIN_ADD:
	case NFT_COMPAT_CHAIN_ZERO:
	case NFT_COMPAT_CHAIN_USER_ADD:
	case NFT_COMPAT_CHAIN_USER_DEL:
	case NFT_COMPAT_CHAIN_USER_FLUSH:
	case NFT_COMPAT_CHAIN_UPDATE:
	case NFT_COMPAT_CHAIN_RENAME:
		snprintf(tcr, sizeof(tcr), "chain %s",
			 nftnl_chain_get_str(o->chain, NFTNL_CHAIN_NAME));
		break;
	case NFT_COMPAT_RULE_APPEND:
	case NFT_COMPAT_RULE_INSERT:
	case NFT_COMPAT_RULE_REPLACE:
	case NFT_COMPAT_RULE_DELETE:
	case NFT_COMPAT_RULE_FLUSH:
		snprintf(tcr, sizeof(tcr), "rule in chain %s",
			 nftnl_rule_get_str(o->rule, NFTNL_RULE_CHAIN));
#if 0
		{
			nft_rule_print_save(o->rule, NFT_RULE_APPEND, FMT_NOCOUNTS);
		}
#endif
		break;
	}

	return snprintf(buf, len, "%s: %s", errmsg, tcr);
}

static int batch_add(struct nft_handle *h, enum obj_update_type type, void *ptr)
{
	struct obj_update *obj;

	obj = calloc(1, sizeof(struct obj_update));
	if (obj == NULL)
		return -1;

	obj->ptr = ptr;
	obj->error.lineno = h->error.lineno;
	obj->type = type;
	list_add_tail(&obj->head, &h->obj_list);
	h->obj_list_num++;

	return 0;
}

static int batch_table_add(struct nft_handle *h, enum obj_update_type type,
			   struct nftnl_table *t)
{
	return batch_add(h, type, t);
}

static int batch_chain_add(struct nft_handle *h, enum obj_update_type type,
			   struct nftnl_chain *c)
{
	return batch_add(h, type, c);
}

static int batch_rule_add(struct nft_handle *h, enum obj_update_type type,
			  struct nftnl_rule *r)
{
	return batch_add(h, type, r);
}

const struct builtin_table xtables_ipv4[NFT_TABLE_MAX] = {
	[NFT_TABLE_RAW] = {
		.name	= "raw",
		.type	= NFT_TABLE_RAW,
		.chains = {
			{
				.name	= "PREROUTING",
				.type	= "filter",
				.prio	= -300,	/* NF_IP_PRI_RAW */
				.hook	= NF_INET_PRE_ROUTING,
			},
			{
				.name	= "OUTPUT",
				.type	= "filter",
				.prio	= -300,	/* NF_IP_PRI_RAW */
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
	[NFT_TABLE_MANGLE] = {
		.name	= "mangle",
		.type	= NFT_TABLE_MANGLE,
		.chains = {
			{
				.name	= "PREROUTING",
				.type	= "filter",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_PRE_ROUTING,
			},
			{
				.name	= "INPUT",
				.type	= "filter",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "FORWARD",
				.type	= "filter",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_FORWARD,
			},
			{
				.name	= "OUTPUT",
				.type	= "route",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_LOCAL_OUT,
			},
			{
				.name	= "POSTROUTING",
				.type	= "filter",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_POST_ROUTING,
			},
		},
	},
	[NFT_TABLE_FILTER] = {
		.name	= "filter",
		.type	= NFT_TABLE_FILTER,
		.chains = {
			{
				.name	= "INPUT",
				.type	= "filter",
				.prio	= 0,	/* NF_IP_PRI_FILTER */
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "FORWARD",
				.type	= "filter",
				.prio	= 0,	/* NF_IP_PRI_FILTER */
				.hook	= NF_INET_FORWARD,
			},
			{
				.name	= "OUTPUT",
				.type	= "filter",
				.prio	= 0,	/* NF_IP_PRI_FILTER */
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
	[NFT_TABLE_SECURITY] = {
		.name	= "security",
		.type	= NFT_TABLE_SECURITY,
		.chains = {
			{
				.name	= "INPUT",
				.type	= "filter",
				.prio	= 150,	/* NF_IP_PRI_SECURITY */
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "FORWARD",
				.type	= "filter",
				.prio	= 150,	/* NF_IP_PRI_SECURITY */
				.hook	= NF_INET_FORWARD,
			},
			{
				.name	= "OUTPUT",
				.type	= "filter",
				.prio	= 150,	/* NF_IP_PRI_SECURITY */
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
	[NFT_TABLE_NAT] = {
		.name	= "nat",
		.type	= NFT_TABLE_NAT,
		.chains = {
			{
				.name	= "PREROUTING",
				.type	= "nat",
				.prio	= -100, /* NF_IP_PRI_NAT_DST */
				.hook	= NF_INET_PRE_ROUTING,
			},
			{
				.name	= "INPUT",
				.type	= "nat",
				.prio	= 100, /* NF_IP_PRI_NAT_SRC */
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "POSTROUTING",
				.type	= "nat",
				.prio	= 100, /* NF_IP_PRI_NAT_SRC */
				.hook	= NF_INET_POST_ROUTING,
			},
			{
				.name	= "OUTPUT",
				.type	= "nat",
				.prio	= -100, /* NF_IP_PRI_NAT_DST */
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
};

#include <linux/netfilter_arp.h>

const struct builtin_table xtables_arp[NFT_TABLE_MAX] = {
	[NFT_TABLE_FILTER] = {
	.name   = "filter",
	.type	= NFT_TABLE_FILTER,
	.chains = {
			{
				.name   = "INPUT",
				.type   = "filter",
				.prio   = NF_IP_PRI_FILTER,
				.hook   = NF_ARP_IN,
			},
			{
				.name   = "OUTPUT",
				.type   = "filter",
				.prio   = NF_IP_PRI_FILTER,
				.hook   = NF_ARP_OUT,
			},
		},
	},
};

#include <linux/netfilter_bridge.h>

const struct builtin_table xtables_bridge[NFT_TABLE_MAX] = {
	[NFT_TABLE_FILTER] = {
		.name = "filter",
		.type	= NFT_TABLE_FILTER,
		.chains = {
			{
				.name   = "INPUT",
				.type   = "filter",
				.prio   = NF_BR_PRI_FILTER_BRIDGED,
				.hook   = NF_BR_LOCAL_IN,
			},
			{
				.name   = "FORWARD",
				.type   = "filter",
				.prio   = NF_BR_PRI_FILTER_BRIDGED,
				.hook   = NF_BR_FORWARD,
			},
			{
				.name   = "OUTPUT",
				.type   = "filter",
				.prio   = NF_BR_PRI_FILTER_BRIDGED,
				.hook   = NF_BR_LOCAL_OUT,
			},
		},
	},
	[NFT_TABLE_NAT] = {
		.name = "nat",
		.type	= NFT_TABLE_NAT,
		.chains = {
			{
				.name   = "PREROUTING",
				.type   = "filter",
				.prio   = NF_BR_PRI_NAT_DST_BRIDGED,
				.hook   = NF_BR_PRE_ROUTING,
			},
			{
				.name   = "OUTPUT",
				.type   = "filter",
				.prio   = NF_BR_PRI_NAT_DST_OTHER,
				.hook   = NF_BR_LOCAL_OUT,
			},
			{
				.name   = "POSTROUTING",
				.type   = "filter",
				.prio   = NF_BR_PRI_NAT_SRC,
				.hook   = NF_BR_POST_ROUTING,
			},
		},
	},
};

static bool nft_table_initialized(const struct nft_handle *h,
				  enum nft_table_type type)
{
	return h->table[type].initialized;
}

static int nft_table_builtin_add(struct nft_handle *h,
				 const struct builtin_table *_t)
{
	struct nftnl_table *t;
	int ret;

	if (nft_table_initialized(h, _t->type))
		return 0;

	t = nftnl_table_alloc();
	if (t == NULL)
		return -1;

	nftnl_table_set(t, NFTNL_TABLE_NAME, (char *)_t->name);

	ret = batch_table_add(h, NFT_COMPAT_TABLE_ADD, t);

	return ret;
}

static struct nftnl_chain *
nft_chain_builtin_alloc(const struct builtin_table *table,
			const struct builtin_chain *chain, int policy)
{
	struct nftnl_chain *c;

	c = nftnl_chain_alloc();
	if (c == NULL)
		return NULL;

	nftnl_chain_set(c, NFTNL_CHAIN_TABLE, (char *)table->name);
	nftnl_chain_set(c, NFTNL_CHAIN_NAME, (char *)chain->name);
	nftnl_chain_set_u32(c, NFTNL_CHAIN_HOOKNUM, chain->hook);
	nftnl_chain_set_u32(c, NFTNL_CHAIN_PRIO, chain->prio);
	nftnl_chain_set_u32(c, NFTNL_CHAIN_POLICY, policy);
	nftnl_chain_set(c, NFTNL_CHAIN_TYPE, (char *)chain->type);

	return c;
}

static void nft_chain_builtin_add(struct nft_handle *h,
				  const struct builtin_table *table,
				  const struct builtin_chain *chain)
{
	struct nftnl_chain *c;

	c = nft_chain_builtin_alloc(table, chain, NF_ACCEPT);
	if (c == NULL)
		return;

	batch_chain_add(h, NFT_COMPAT_CHAIN_ADD, c);
	nftnl_chain_list_add_tail(c, h->table[table->type].chain_cache);
}

/* find if built-in table already exists */
const struct builtin_table *
nft_table_builtin_find(struct nft_handle *h, const char *table)
{
	int i;
	bool found = false;

	for (i = 0; i < NFT_TABLE_MAX; i++) {
		if (h->tables[i].name == NULL)
			continue;

		if (strcmp(h->tables[i].name, table) != 0)
			continue;

		found = true;
		break;
	}

	return found ? &h->tables[i] : NULL;
}

/* find if built-in chain already exists */
const struct builtin_chain *
nft_chain_builtin_find(const struct builtin_table *t, const char *chain)
{
	int i;
	bool found = false;

	for (i=0; i<NF_IP_NUMHOOKS && t->chains[i].name != NULL; i++) {
		if (strcmp(t->chains[i].name, chain) != 0)
			continue;

		found = true;
		break;
	}
	return found ? &t->chains[i] : NULL;
}

static void nft_chain_builtin_init(struct nft_handle *h,
				   const struct builtin_table *table)
{
	struct nftnl_chain_list *list = nft_chain_list_get(h, table->name);
	struct nftnl_chain *c;
	int i;

	if (!list)
		return;

	/* Initialize built-in chains if they don't exist yet */
	for (i=0; i < NF_INET_NUMHOOKS && table->chains[i].name != NULL; i++) {

		c = nftnl_chain_list_lookup_byname(list, table->chains[i].name);
		if (c != NULL)
			continue;

		nft_chain_builtin_add(h, table, &table->chains[i]);
	}
}

static int nft_xt_builtin_init(struct nft_handle *h, const char *table)
{
	const struct builtin_table *t;

	t = nft_table_builtin_find(h, table);
	if (t == NULL)
		return -1;

	if (nft_table_initialized(h, t->type))
		return 0;

	if (nft_table_builtin_add(h, t) < 0)
		return -1;

	nft_chain_builtin_init(h, t);

	h->table[t->type].initialized = true;

	return 0;
}

static bool nft_chain_builtin(struct nftnl_chain *c)
{
	/* Check if this chain has hook number, in that case is built-in.
	 * Should we better export the flags to user-space via nf_tables?
	 */
	return nftnl_chain_get(c, NFTNL_CHAIN_HOOKNUM) != NULL;
}

static int nft_restart(struct nft_handle *h)
{
	mnl_socket_close(h->nl);

	h->nl = mnl_socket_open(NETLINK_NETFILTER);
	if (h->nl == NULL)
		return -1;

	if (mnl_socket_bind(h->nl, 0, MNL_SOCKET_AUTOPID) < 0)
		return -1;

	h->portid = mnl_socket_get_portid(h->nl);

	return 0;
}

int nft_init(struct nft_handle *h, const struct builtin_table *t)
{
	h->nl = mnl_socket_open(NETLINK_NETFILTER);
	if (h->nl == NULL)
		return -1;

	if (mnl_socket_bind(h->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		mnl_socket_close(h->nl);
		return -1;
	}

	h->portid = mnl_socket_get_portid(h->nl);
	h->tables = t;

	INIT_LIST_HEAD(&h->obj_list);
	INIT_LIST_HEAD(&h->err_list);

	return 0;
}

static int __flush_rule_cache(struct nftnl_rule *r, void *data)
{
	nftnl_rule_list_del(r);
	nftnl_rule_free(r);

	return 0;
}

static void flush_rule_cache(struct nftnl_chain *c)
{
	nftnl_rule_foreach(c, __flush_rule_cache, NULL);
}

static int __flush_chain_cache(struct nftnl_chain *c, void *data)
{
	nftnl_chain_list_del(c);
	nftnl_chain_free(c);

	return 0;
}

static void flush_chain_cache(struct nft_handle *h, const char *tablename)
{
	const struct builtin_table *table;
	int i;

	if (tablename) {
		table = nft_table_builtin_find(h, tablename);
		if (!table || !h->table[table->type].chain_cache)
			return;
		nftnl_chain_list_foreach(h->table[table->type].chain_cache,
					 __flush_chain_cache, NULL);
		return;
	}

	for (i = 0; i < NFT_TABLE_MAX; i++) {
		if (h->tables[i].name == NULL)
			continue;

		if (!h->table[i].chain_cache)
			continue;

		nftnl_chain_list_free(h->table[i].chain_cache);
		h->table[i].chain_cache = NULL;
	}
	h->have_cache = false;
}

void nft_fini(struct nft_handle *h)
{
	flush_chain_cache(h, NULL);
	mnl_socket_close(h->nl);
}

static void nft_chain_print_debug(struct nftnl_chain *c, struct nlmsghdr *nlh)
{
#ifdef NLDEBUG
	char tmp[1024];

	nftnl_chain_snprintf(tmp, sizeof(tmp), c, 0, 0);
	printf("DEBUG: chain: %s\n", tmp);
	mnl_nlmsg_fprintf(stdout, nlh, nlh->nlmsg_len, sizeof(struct nfgenmsg));
#endif
}

static struct nftnl_chain *nft_chain_new(struct nft_handle *h,
				       const char *table, const char *chain,
				       int policy,
				       const struct xt_counters *counters)
{
	struct nftnl_chain *c;
	const struct builtin_table *_t;
	const struct builtin_chain *_c;

	_t = nft_table_builtin_find(h, table);
	if (!_t) {
		errno = ENXIO;
		return NULL;
	}

	/* if this built-in table does not exists, create it */
	nft_table_builtin_add(h, _t);

	_c = nft_chain_builtin_find(_t, chain);
	if (_c != NULL) {
		/* This is a built-in chain */
		c = nft_chain_builtin_alloc(_t, _c, policy);
		if (c == NULL)
			return NULL;
	} else {
		errno = ENOENT;
		return NULL;
	}

	if (counters) {
		nftnl_chain_set_u64(c, NFTNL_CHAIN_BYTES,
					counters->bcnt);
		nftnl_chain_set_u64(c, NFTNL_CHAIN_PACKETS,
					counters->pcnt);
	}

	return c;
}

int nft_chain_set(struct nft_handle *h, const char *table,
		  const char *chain, const char *policy,
		  const struct xt_counters *counters)
{
	struct nftnl_chain *c = NULL;
	int ret;

	nft_fn = nft_chain_set;

	if (strcmp(policy, "DROP") == 0)
		c = nft_chain_new(h, table, chain, NF_DROP, counters);
	else if (strcmp(policy, "ACCEPT") == 0)
		c = nft_chain_new(h, table, chain, NF_ACCEPT, counters);
	else
		errno = EINVAL;

	if (c == NULL)
		return 0;

	ret = batch_chain_add(h, NFT_COMPAT_CHAIN_UPDATE, c);

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

static int __add_match(struct nftnl_expr *e, struct xt_entry_match *m)
{
	void *info;

	nftnl_expr_set(e, NFTNL_EXPR_MT_NAME, m->u.user.name, strlen(m->u.user.name));
	nftnl_expr_set_u32(e, NFTNL_EXPR_MT_REV, m->u.user.revision);

	info = calloc(1, m->u.match_size);
	if (info == NULL)
		return -ENOMEM;

	memcpy(info, m->data, m->u.match_size - sizeof(*m));
	nftnl_expr_set(e, NFTNL_EXPR_MT_INFO, info, m->u.match_size - sizeof(*m));

	return 0;
}

static int add_nft_limit(struct nftnl_rule *r, struct xt_entry_match *m)
{
	struct xt_rateinfo *rinfo = (void *)m->data;
	static const uint32_t mult[] = {
		XT_LIMIT_SCALE*24*60*60,	/* day */
		XT_LIMIT_SCALE*60*60,		/* hour */
		XT_LIMIT_SCALE*60,		/* min */
		XT_LIMIT_SCALE,			/* sec */
	};
	struct nftnl_expr *expr;
	int i;

	expr = nftnl_expr_alloc("limit");
	if (!expr)
		return -ENOMEM;

	for (i = 1; i < ARRAY_SIZE(mult); i++) {
		if (rinfo->avg > mult[i] ||
		    mult[i] / rinfo->avg < mult[i] % rinfo->avg)
			break;
	}

	nftnl_expr_set_u32(expr, NFTNL_EXPR_LIMIT_TYPE, NFT_LIMIT_PKTS);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_LIMIT_FLAGS, 0);

	nftnl_expr_set_u64(expr, NFTNL_EXPR_LIMIT_RATE,
			   mult[i - 1] / rinfo->avg);
        nftnl_expr_set_u64(expr, NFTNL_EXPR_LIMIT_UNIT,
			   mult[i - 1] / XT_LIMIT_SCALE);

	nftnl_expr_set_u32(expr, NFTNL_EXPR_LIMIT_BURST, rinfo->burst);

	nftnl_rule_add_expr(r, expr);
	return 0;
}

int add_match(struct nftnl_rule *r, struct xt_entry_match *m)
{
	struct nftnl_expr *expr;
	int ret;

	if (!strcmp(m->u.user.name, "limit"))
		return add_nft_limit(r, m);

	expr = nftnl_expr_alloc("match");
	if (expr == NULL)
		return -ENOMEM;

	ret = __add_match(expr, m);
	nftnl_rule_add_expr(r, expr);

	return ret;
}

static int __add_target(struct nftnl_expr *e, struct xt_entry_target *t)
{
	void *info;

	nftnl_expr_set(e, NFTNL_EXPR_TG_NAME, t->u.user.name,
			  strlen(t->u.user.name));
	nftnl_expr_set_u32(e, NFTNL_EXPR_TG_REV, t->u.user.revision);

	info = calloc(1, t->u.target_size);
	if (info == NULL)
		return -ENOMEM;

	memcpy(info, t->data, t->u.target_size - sizeof(*t));
	nftnl_expr_set(e, NFTNL_EXPR_TG_INFO, info, t->u.target_size - sizeof(*t));

	return 0;
}

static int add_meta_nftrace(struct nftnl_rule *r)
{
	struct nftnl_expr *expr;

	expr = nftnl_expr_alloc("immediate");
	if (expr == NULL)
		return -ENOMEM;

	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG32_01);
	nftnl_expr_set_u8(expr, NFTNL_EXPR_IMM_DATA, 1);
	nftnl_rule_add_expr(r, expr);

	expr = nftnl_expr_alloc("meta");
	if (expr == NULL)
		return -ENOMEM;
	nftnl_expr_set_u32(expr, NFTNL_EXPR_META_KEY, NFT_META_NFTRACE);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_META_SREG, NFT_REG32_01);

	nftnl_rule_add_expr(r, expr);
	return 0;
}

int add_target(struct nftnl_rule *r, struct xt_entry_target *t)
{
	struct nftnl_expr *expr;
	int ret;

	if (strcmp(t->u.user.name, "TRACE") == 0)
		return add_meta_nftrace(r);

	expr = nftnl_expr_alloc("target");
	if (expr == NULL)
		return -ENOMEM;

	ret = __add_target(expr, t);
	nftnl_rule_add_expr(r, expr);

	return ret;
}

int add_jumpto(struct nftnl_rule *r, const char *name, int verdict)
{
	struct nftnl_expr *expr;

	expr = nftnl_expr_alloc("immediate");
	if (expr == NULL)
		return -ENOMEM;

	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_VERDICT, verdict);
	nftnl_expr_set_str(expr, NFTNL_EXPR_IMM_CHAIN, (char *)name);
	nftnl_rule_add_expr(r, expr);

	return 0;
}

int add_verdict(struct nftnl_rule *r, int verdict)
{
	struct nftnl_expr *expr;

	expr = nftnl_expr_alloc("immediate");
	if (expr == NULL)
		return -ENOMEM;

	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_VERDICT, verdict);
	nftnl_rule_add_expr(r, expr);

	return 0;
}

int add_action(struct nftnl_rule *r, struct iptables_command_state *cs,
	       bool goto_set)
{
       int ret = 0;

       /* If no target at all, add nothing (default to continue) */
       if (cs->target != NULL) {
	       /* Standard target? */
	       if (strcmp(cs->jumpto, XTC_LABEL_ACCEPT) == 0)
		       ret = add_verdict(r, NF_ACCEPT);
	       else if (strcmp(cs->jumpto, XTC_LABEL_DROP) == 0)
		       ret = add_verdict(r, NF_DROP);
	       else if (strcmp(cs->jumpto, XTC_LABEL_RETURN) == 0)
		       ret = add_verdict(r, NFT_RETURN);
	       else
		       ret = add_target(r, cs->target->t);
       } else if (strlen(cs->jumpto) > 0) {
	       /* Not standard, then it's a go / jump to chain */
	       if (goto_set)
		       ret = add_jumpto(r, cs->jumpto, NFT_GOTO);
	       else
		       ret = add_jumpto(r, cs->jumpto, NFT_JUMP);
       }
       return ret;
}

static void nft_rule_print_debug(struct nftnl_rule *r, struct nlmsghdr *nlh)
{
#ifdef NLDEBUG
	char tmp[1024];

	nftnl_rule_snprintf(tmp, sizeof(tmp), r, 0, 0);
	printf("DEBUG: rule: %s\n", tmp);
	mnl_nlmsg_fprintf(stdout, nlh, nlh->nlmsg_len, sizeof(struct nfgenmsg));
#endif
}

int add_counters(struct nftnl_rule *r, uint64_t packets, uint64_t bytes)
{
	struct nftnl_expr *expr;

	expr = nftnl_expr_alloc("counter");
	if (expr == NULL)
		return -ENOMEM;

	nftnl_expr_set_u64(expr, NFTNL_EXPR_CTR_PACKETS, packets);
	nftnl_expr_set_u64(expr, NFTNL_EXPR_CTR_BYTES, bytes);

	nftnl_rule_add_expr(r, expr);

	return 0;
}

enum udata_type {
	UDATA_TYPE_COMMENT,
	__UDATA_TYPE_MAX,
};
#define UDATA_TYPE_MAX (__UDATA_TYPE_MAX - 1)

static int parse_udata_cb(const struct nftnl_udata *attr, void *data)
{
	unsigned char *value = nftnl_udata_get(attr);
	uint8_t type = nftnl_udata_type(attr);
	uint8_t len = nftnl_udata_len(attr);
	const struct nftnl_udata **tb = data;

	switch (type) {
	case UDATA_TYPE_COMMENT:
		if (value[len - 1] != '\0')
			return -1;
		break;
	default:
		return 0;
	}
	tb[type] = attr;
	return 0;
}

char *get_comment(const void *data, uint32_t data_len)
{
	const struct nftnl_udata *tb[UDATA_TYPE_MAX + 1] = {};

	if (nftnl_udata_parse(data, data_len, parse_udata_cb, tb) < 0)
		return NULL;

	if (!tb[UDATA_TYPE_COMMENT])
		return NULL;

	return nftnl_udata_get(tb[UDATA_TYPE_COMMENT]);
}

void add_compat(struct nftnl_rule *r, uint32_t proto, bool inv)
{
	nftnl_rule_set_u32(r, NFTNL_RULE_COMPAT_PROTO, proto);
	nftnl_rule_set_u32(r, NFTNL_RULE_COMPAT_FLAGS,
			      inv ? NFT_RULE_COMPAT_F_INV : 0);
}

static struct nftnl_rule *
nft_rule_new(struct nft_handle *h, const char *chain, const char *table,
	     void *data)
{
	struct nftnl_rule *r;

	r = nftnl_rule_alloc();
	if (r == NULL)
		return NULL;

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, h->family);
	nftnl_rule_set(r, NFTNL_RULE_TABLE, (char *)table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, (char *)chain);

	if (h->ops->add(r, data) < 0)
		goto err;

	return r;
err:
	nftnl_rule_free(r);
	return NULL;
}

static struct nftnl_chain *
nft_chain_find(struct nft_handle *h, const char *table, const char *chain);

int
nft_rule_append(struct nft_handle *h, const char *chain, const char *table,
		void *data, struct nftnl_rule *ref, bool verbose)
{
	struct nftnl_chain *c;
	struct nftnl_rule *r;
	int type;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_xt_builtin_init(h, table);

	nft_fn = nft_rule_append;

	r = nft_rule_new(h, chain, table, data);
	if (r == NULL)
		return 0;

	if (ref) {
		nftnl_rule_set_u64(r, NFTNL_RULE_HANDLE,
				   nftnl_rule_get_u64(ref, NFTNL_RULE_HANDLE));
		type = NFT_COMPAT_RULE_REPLACE;
	} else
		type = NFT_COMPAT_RULE_APPEND;

	if (batch_rule_add(h, type, r) < 0) {
		nftnl_rule_free(r);
		return 0;
	}

	if (verbose)
		h->ops->print_rule(r, 0, FMT_PRINT_RULE);

	if (ref) {
		nftnl_chain_rule_insert_at(r, ref);
		nftnl_chain_rule_del(r);
	} else {
		c = nft_chain_find(h, table, chain);
		if (!c) {
			errno = ENOENT;
			return 0;
		}
		nftnl_chain_rule_add_tail(r, c);
	}

	return 1;
}

void
nft_rule_print_save(const struct nftnl_rule *r, enum nft_rule_print type,
		    unsigned int format)
{
	const char *chain = nftnl_rule_get_str(r, NFTNL_RULE_CHAIN);
	int family = nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY);
	struct iptables_command_state cs = {};
	struct nft_family_ops *ops;

	ops = nft_family_ops_lookup(family);
	ops->rule_to_cs(r, &cs);

	if (!(format & (FMT_NOCOUNTS | FMT_C_COUNTS)) && ops->save_counters)
		ops->save_counters(&cs);

	/* print chain name */
	switch(type) {
	case NFT_RULE_APPEND:
		printf("-A %s ", chain);
		break;
	case NFT_RULE_DEL:
		printf("-D %s ", chain);
		break;
	}

	if (ops->save_rule)
		ops->save_rule(&cs, format);

	if (ops->clear_cs)
		ops->clear_cs(&cs);
}

static int nftnl_chain_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_handle *h = data;
	const struct builtin_table *t;
	struct nftnl_chain *c;

	c = nftnl_chain_alloc();
	if (c == NULL)
		goto err;

	if (nftnl_chain_nlmsg_parse(nlh, c) < 0)
		goto out;

	t = nft_table_builtin_find(h,
			nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE));
	if (!t)
		goto out;

	nftnl_chain_list_add_tail(c, h->table[t->type].chain_cache);

	return MNL_CB_OK;
out:
	nftnl_chain_free(c);
err:
	return MNL_CB_OK;
}

static int fetch_chain_cache(struct nft_handle *h)
{
	char buf[16536];
	struct nlmsghdr *nlh;
	int i, ret;

retry:
	for (i = 0; i < NFT_TABLE_MAX; i++) {
		enum nft_table_type type = h->tables[i].type;

		if (!h->tables[i].name)
			continue;

		h->table[type].chain_cache = nftnl_chain_list_alloc();
		if (!h->table[type].chain_cache)
			return -1;
	}

	nlh = nftnl_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN, h->family,
					NLM_F_DUMP, h->seq);

	ret = mnl_talk(h, nlh, nftnl_chain_list_cb, h);
	if (ret < 0 && errno == EINTR) {
		assert(nft_restart(h) >= 0);
		flush_chain_cache(h, NULL);
		goto retry;
	}

	return ret;
}

static int nftnl_rule_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_chain *c = data;
	struct nftnl_rule *r;

	r = nftnl_rule_alloc();
	if (r == NULL)
		return MNL_CB_OK;

	if (nftnl_rule_nlmsg_parse(nlh, r) < 0) {
		nftnl_rule_free(r);
		return MNL_CB_OK;
	}

	nftnl_chain_rule_add_tail(r, c);
	return MNL_CB_OK;
}

static int nft_rule_list_update(struct nftnl_chain *c, void *data)
{
	struct nft_handle *h = data;
	char buf[16536];
	struct nlmsghdr *nlh;
	struct nftnl_rule *rule;
	int ret;

	rule = nftnl_rule_alloc();
	if (!rule)
		return -1;

	nftnl_rule_set_str(rule, NFTNL_RULE_TABLE,
			   nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE));
	nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN,
			   nftnl_chain_get_str(c, NFTNL_CHAIN_NAME));

retry:
	nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, h->family,
					NLM_F_DUMP, h->seq);
	nftnl_rule_nlmsg_build_payload(nlh, rule);

	ret = mnl_talk(h, nlh, nftnl_rule_list_cb, c);
	if (ret < 0) {
		flush_rule_cache(c);

		if (errno == EINTR) {
			assert(nft_restart(h) >= 0);
			goto retry;
		}
		nftnl_rule_free(rule);
		return -1;
	}

	nftnl_rule_free(rule);
	return 0;
}

static int fetch_rule_cache(struct nft_handle *h)
{
	int i;

	for (i = 0; i < NFT_TABLE_MAX; i++) {
		enum nft_table_type type = h->tables[i].type;

		if (!h->tables[i].name)
			continue;

		if (nftnl_chain_list_foreach(h->table[type].chain_cache,
					     nft_rule_list_update, h))
			return -1;
	}
	return 0;
}

struct nftnl_chain_list *nft_chain_list_get(struct nft_handle *h,
					    const char *table)
{
	const struct builtin_table *t;

	t = nft_table_builtin_find(h, table);
	if (!t)
		return NULL;

	if (!h->have_cache) {
		fetch_chain_cache(h);
		fetch_rule_cache(h);
		h->have_cache = true;
	}

	return h->table[t->type].chain_cache;
}

static const char *policy_name[NF_ACCEPT+1] = {
	[NF_DROP] = "DROP",
	[NF_ACCEPT] = "ACCEPT",
};

int nft_chain_save(struct nft_handle *h, struct nftnl_chain_list *list)
{
	struct nftnl_chain_list_iter *iter;
	struct nft_family_ops *ops;
	struct nftnl_chain *c;

	ops = nft_family_ops_lookup(h->family);

	iter = nftnl_chain_list_iter_create(list);
	if (iter == NULL)
		return 0;

	c = nftnl_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *policy = NULL;

		if (nft_chain_builtin(c)) {
			uint32_t pol = NF_ACCEPT;

			if (nftnl_chain_get(c, NFTNL_CHAIN_POLICY))
				pol = nftnl_chain_get_u32(c, NFTNL_CHAIN_POLICY);
			policy = policy_name[pol];
		}

		if (ops->save_chain)
			ops->save_chain(c, policy);

		c = nftnl_chain_list_iter_next(iter);
	}

	nftnl_chain_list_iter_destroy(iter);

	return 1;
}

static int nft_chain_save_rules(struct nft_handle *h,
				struct nftnl_chain *c, unsigned int format)
{
	struct nftnl_rule_iter *iter;
	struct nftnl_rule *r;

	iter = nftnl_rule_iter_create(c);
	if (iter == NULL)
		return 1;

	r = nftnl_rule_iter_next(iter);
	while (r != NULL) {
		nft_rule_print_save(r, NFT_RULE_APPEND, format);
		r = nftnl_rule_iter_next(iter);
	}

	nftnl_rule_iter_destroy(iter);
	return 0;
}

int nft_rule_save(struct nft_handle *h, const char *table, unsigned int format)
{
	struct nftnl_chain_list_iter *iter;
	struct nftnl_chain_list *list;
	struct nftnl_chain *c;
	int ret = 0;

	list = nft_chain_list_get(h, table);
	if (!list)
		return 0;

	iter = nftnl_chain_list_iter_create(list);
	if (!iter)
		return 0;

	c = nftnl_chain_list_iter_next(iter);
	while (c) {
		ret = nft_chain_save_rules(h, c, format);
		if (ret != 0)
			break;

		c = nftnl_chain_list_iter_next(iter);
	}

	nftnl_chain_list_iter_destroy(iter);

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

static void
__nft_rule_flush(struct nft_handle *h, const char *table,
		 const char *chain, bool verbose)
{
	struct nftnl_rule *r;

	if (verbose)
		fprintf(stdout, "Flushing chain `%s'\n", chain);

	r = nftnl_rule_alloc();
	if (r == NULL)
		return;

	nftnl_rule_set(r, NFTNL_RULE_TABLE, (char *)table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, (char *)chain);

	if (batch_rule_add(h, NFT_COMPAT_RULE_FLUSH, r) < 0)
		nftnl_rule_free(r);
}

struct chain_user_flush_data {
	struct nft_handle	*handle;
	const char		*table;
	const char		*chain;
};

static int __nft_chain_user_flush(struct nftnl_chain *c, void *data)
{
	const char *table_name = nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE);
	const char *chain_name = nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);
	struct chain_user_flush_data *d = data;
	struct nft_handle *h = d->handle;
	const char *table = d->table;
	const char *chain = d->chain;

	if (strcmp(table, table_name) != 0)
		return 0;

	if (strcmp(chain, chain_name) != 0)
		return 0;

	if (!nftnl_chain_is_set(c, NFTNL_CHAIN_HOOKNUM))
		__nft_rule_flush(h, table, chain, false);

	return 0;
}

int nft_chain_user_flush(struct nft_handle *h, struct nftnl_chain_list *list,
			 const char *table, const char *chain)
{
	struct chain_user_flush_data d = {
		.handle = h,
		.table	= table,
		.chain  = chain,
	};

	nft_fn = nft_chain_user_flush;

	nftnl_chain_list_foreach(list, __nft_chain_user_flush, &d);

	return 1;
}

int nft_rule_flush(struct nft_handle *h, const char *chain, const char *table,
		   bool verbose)
{
	int ret = 0;
	struct nftnl_chain_list *list;
	struct nftnl_chain_list_iter *iter;
	struct nftnl_chain *c;

	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_xt_builtin_init(h, table);

	nft_fn = nft_rule_flush;

	list = nft_chain_list_get(h, table);
	if (list == NULL) {
		ret = 1;
		goto err;
	}

	if (chain) {
		c = nftnl_chain_list_lookup_byname(list, chain);
		if (!c)
			return 0;

		__nft_rule_flush(h, table, chain, verbose);
		flush_rule_cache(c);
		return 1;
	}

	iter = nftnl_chain_list_iter_create(list);
	if (iter == NULL) {
		ret = 1;
		goto err;
	}

	c = nftnl_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *chain_name =
			nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);

		__nft_rule_flush(h, table, chain_name, verbose);
		flush_rule_cache(c);
		c = nftnl_chain_list_iter_next(iter);
	}
	nftnl_chain_list_iter_destroy(iter);
err:
	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

int nft_chain_user_add(struct nft_handle *h, const char *chain, const char *table)
{
	struct nftnl_chain_list *list;
	struct nftnl_chain *c;
	int ret;

	nft_fn = nft_chain_user_add;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_xt_builtin_init(h, table);

	c = nftnl_chain_alloc();
	if (c == NULL)
		return 0;

	nftnl_chain_set(c, NFTNL_CHAIN_TABLE, (char *)table);
	nftnl_chain_set(c, NFTNL_CHAIN_NAME, (char *)chain);

	ret = batch_chain_add(h, NFT_COMPAT_CHAIN_USER_ADD, c);

	list = nft_chain_list_get(h, table);
	if (list)
		nftnl_chain_list_add(c, list);

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

/* From linux/netlink.h */
#ifndef NLM_F_NONREC
#define NLM_F_NONREC	0x100	/* Do not delete recursively    */
#endif

struct chain_user_del_data {
	struct nft_handle	*handle;
	bool			verbose;
	int			builtin_err;
};

static int __nft_chain_user_del(struct nftnl_chain *c, void *data)
{
	struct chain_user_del_data *d = data;
	struct nft_handle *h = d->handle;
	int ret;

	/* don't delete built-in chain */
	if (nft_chain_builtin(c))
		return d->builtin_err;

	if (d->verbose)
		fprintf(stdout, "Deleting chain `%s'\n",
			nftnl_chain_get_str(c, NFTNL_CHAIN_NAME));

	/* XXX This triggers a fast lookup from the kernel. */
	nftnl_chain_unset(c, NFTNL_CHAIN_HANDLE);
	ret = batch_chain_add(h, NFT_COMPAT_CHAIN_USER_DEL, c);
	if (ret)
		return -1;

	nftnl_chain_list_del(c);
	return 0;
}

int nft_chain_user_del(struct nft_handle *h, const char *chain,
		       const char *table, bool verbose)
{
	struct chain_user_del_data d = {
		.handle = h,
		.verbose = verbose,
	};
	struct nftnl_chain_list *list;
	struct nftnl_chain *c;
	int ret = 0;

	nft_fn = nft_chain_user_del;

	list = nft_chain_list_get(h, table);
	if (list == NULL)
		return 0;

	if (chain) {
		c = nftnl_chain_list_lookup_byname(list, chain);
		if (!c) {
			errno = ENOENT;
			return 0;
		}
		d.builtin_err = -2;
		ret = __nft_chain_user_del(c, &d);
		if (ret == -2)
			errno = EINVAL;
		goto out;
	}

	ret = nftnl_chain_list_foreach(list, __nft_chain_user_del, &d);
out:
	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

static struct nftnl_chain *
nft_chain_find(struct nft_handle *h, const char *table, const char *chain)
{
	struct nftnl_chain_list *list;

	list = nft_chain_list_get(h, table);
	if (list == NULL)
		return NULL;

	return nftnl_chain_list_lookup_byname(list, chain);
}

bool nft_chain_exists(struct nft_handle *h,
		      const char *table, const char *chain)
{
	const struct builtin_table *t = nft_table_builtin_find(h, table);

	/* xtables does not support custom tables */
	if (!t)
		return false;

	if (nft_chain_builtin_find(t, chain))
		return true;

	return !!nft_chain_find(h, table, chain);
}

int nft_chain_user_rename(struct nft_handle *h,const char *chain,
			  const char *table, const char *newname)
{
	struct nftnl_chain *c;
	uint64_t handle;
	int ret;

	nft_fn = nft_chain_user_add;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_xt_builtin_init(h, table);

	/* Config load changed errno. Ensure genuine info for our callers. */
	errno = 0;

	/* Find the old chain to be renamed */
	c = nft_chain_find(h, table, chain);
	if (c == NULL) {
		errno = ENOENT;
		return 0;
	}
	handle = nftnl_chain_get_u64(c, NFTNL_CHAIN_HANDLE);

	/* Now prepare the new name for the chain */
	c = nftnl_chain_alloc();
	if (c == NULL)
		return 0;

	nftnl_chain_set(c, NFTNL_CHAIN_TABLE, (char *)table);
	nftnl_chain_set(c, NFTNL_CHAIN_NAME, (char *)newname);
	nftnl_chain_set_u64(c, NFTNL_CHAIN_HANDLE, handle);

	ret = batch_chain_add(h, NFT_COMPAT_CHAIN_RENAME, c);

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

static int nftnl_table_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_table *t;
	struct nftnl_table_list *list = data;

	t = nftnl_table_alloc();
	if (t == NULL)
		goto err;

	if (nftnl_table_nlmsg_parse(nlh, t) < 0)
		goto out;

	nftnl_table_list_add_tail(t, list);

	return MNL_CB_OK;
out:
	nftnl_table_free(t);
err:
	return MNL_CB_OK;
}

static struct nftnl_table_list *nftnl_table_list_get(struct nft_handle *h)
{
	char buf[16536];
	struct nlmsghdr *nlh;
	struct nftnl_table_list *list;
	int ret;

retry:
	list = nftnl_table_list_alloc();
	if (list == NULL)
		return 0;

	nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE, h->family,
					NLM_F_DUMP, h->seq);

	ret = mnl_talk(h, nlh, nftnl_table_list_cb, list);
	if (ret < 0 && errno == EINTR) {
		assert(nft_restart(h) >= 0);
		nftnl_table_list_free(list);
		goto retry;
	}

	return list;
}

bool nft_table_find(struct nft_handle *h, const char *tablename)
{
	struct nftnl_table_list *list;
	struct nftnl_table_list_iter *iter;
	struct nftnl_table *t;
	bool ret = false;

	list = nftnl_table_list_get(h);
	if (list == NULL)
		goto err;

	iter = nftnl_table_list_iter_create(list);
	if (iter == NULL)
		goto err;

	t = nftnl_table_list_iter_next(iter);
	while (t != NULL) {
		const char *this_tablename =
			nftnl_table_get(t, NFTNL_TABLE_NAME);

		if (strcmp(tablename, this_tablename) == 0) {
			ret = true;
			break;
		}

		t = nftnl_table_list_iter_next(iter);
	}

	nftnl_table_list_iter_destroy(iter);
	nftnl_table_list_free(list);

err:
	return ret;
}

int nft_for_each_table(struct nft_handle *h,
		       int (*func)(struct nft_handle *h, const char *tablename, bool counters),
		       bool counters)
{
	struct nftnl_table_list *list;
	struct nftnl_table_list_iter *iter;
	struct nftnl_table *t;

	list = nftnl_table_list_get(h);
	if (list == NULL)
		return -1;

	iter = nftnl_table_list_iter_create(list);
	if (iter == NULL)
		return -1;

	t = nftnl_table_list_iter_next(iter);
	while (t != NULL) {
		const char *tablename =
			nftnl_table_get(t, NFTNL_TABLE_NAME);

		func(h, tablename, counters);

		t = nftnl_table_list_iter_next(iter);
	}

	nftnl_table_list_iter_destroy(iter);
	nftnl_table_list_free(list);
	return 0;
}

static int __nft_table_flush(struct nft_handle *h, const char *table)
{
	const struct builtin_table *_t;
	struct nftnl_table *t;

	t = nftnl_table_alloc();
	if (t == NULL)
		return -1;

	nftnl_table_set_str(t, NFTNL_TABLE_NAME, table);

	batch_table_add(h, NFT_COMPAT_TABLE_FLUSH, t);

	_t = nft_table_builtin_find(h, table);
	assert(_t);
	h->table[_t->type].initialized = false;

	flush_chain_cache(h, table);

	return 0;
}

int nft_table_flush(struct nft_handle *h, const char *table)
{
	struct nftnl_table_list_iter *iter;
	struct nftnl_table_list *list;
	struct nftnl_table *t;
	int ret = 0;

	nft_fn = nft_table_flush;

	list = nftnl_table_list_get(h);
	if (list == NULL) {
		ret = -1;
		goto err_out;
	}

	iter = nftnl_table_list_iter_create(list);
	if (iter == NULL) {
		ret = -1;
		goto err_table_list;
	}

	t = nftnl_table_list_iter_next(iter);
	while (t != NULL) {
		const char *table_name =
			nftnl_table_get_str(t, NFTNL_TABLE_NAME);

		if (strcmp(table_name, table) != 0)
			goto next;

		ret = __nft_table_flush(h, table);
		if (ret < 0)
			goto err_table_iter;
next:
		t = nftnl_table_list_iter_next(iter);
	}

err_table_iter:
	nftnl_table_list_iter_destroy(iter);
err_table_list:
	nftnl_table_list_free(list);
err_out:
	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

void nft_table_new(struct nft_handle *h, const char *table)
{
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_xt_builtin_init(h, table);
}

static int __nft_rule_del(struct nft_handle *h, struct nftnl_rule *r)
{
	int ret;

	nftnl_rule_list_del(r);

	ret = batch_rule_add(h, NFT_COMPAT_RULE_DELETE, r);
	if (ret < 0) {
		nftnl_rule_free(r);
		return -1;
	}
	return 1;
}

static struct nftnl_rule *
nft_rule_find(struct nft_handle *h, struct nftnl_chain *c, void *data, int rulenum)
{
	struct nftnl_rule *r;
	struct nftnl_rule_iter *iter;
	bool found = false;

	if (rulenum >= 0)
		/* Delete by rule number case */
		return nftnl_rule_lookup_byindex(c, rulenum);

	iter = nftnl_rule_iter_create(c);
	if (iter == NULL)
		return 0;

	r = nftnl_rule_iter_next(iter);
	while (r != NULL) {
		found = h->ops->rule_find(h->ops, r, data);
		if (found)
			break;
		r = nftnl_rule_iter_next(iter);
	}

	nftnl_rule_iter_destroy(iter);

	return found ? r : NULL;
}

int nft_rule_check(struct nft_handle *h, const char *chain,
		   const char *table, void *data, bool verbose)
{
	struct nftnl_chain *c;
	struct nftnl_rule *r;

	nft_fn = nft_rule_check;

	c = nft_chain_find(h, table, chain);
	if (!c)
		goto fail_enoent;

	r = nft_rule_find(h, c, data, -1);
	if (r == NULL)
		goto fail_enoent;

	if (verbose)
		h->ops->print_rule(r, 0, FMT_PRINT_RULE);

	return 1;
fail_enoent:
	errno = ENOENT;
	return 0;
}

int nft_rule_delete(struct nft_handle *h, const char *chain,
		    const char *table, void *data, bool verbose)
{
	int ret = 0;
	struct nftnl_chain *c;
	struct nftnl_rule *r;

	nft_fn = nft_rule_delete;

	c = nft_chain_find(h, table, chain);
	if (!c) {
		errno = ENOENT;
		return 0;
	}

	r = nft_rule_find(h, c, data, -1);
	if (r != NULL) {
		ret =__nft_rule_del(h, r);
		if (ret < 0)
			errno = ENOMEM;
		if (verbose)
			h->ops->print_rule(r, 0, FMT_PRINT_RULE);
	} else
		errno = ENOENT;

	return ret;
}

static struct nftnl_rule *
nft_rule_add(struct nft_handle *h, const char *chain,
	     const char *table, struct iptables_command_state *cs,
	     struct nftnl_rule *ref, bool verbose)
{
	struct nftnl_rule *r;
	uint64_t ref_id;

	r = nft_rule_new(h, chain, table, cs);
	if (r == NULL)
		return NULL;

	if (ref) {
		ref_id = nftnl_rule_get_u64(ref, NFTNL_RULE_HANDLE);
		if (ref_id > 0) {
			nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, ref_id);
			DEBUGP("adding after rule handle %"PRIu64"\n", ref_id);
		} else {
			ref_id = nftnl_rule_get_u32(ref, NFTNL_RULE_ID);
			if (!ref_id) {
				ref_id = ++h->rule_id;
				nftnl_rule_set_u32(ref, NFTNL_RULE_ID, ref_id);
			}
			nftnl_rule_set_u32(r, NFTNL_RULE_POSITION_ID, ref_id);
			DEBUGP("adding after rule ID %"PRIu64"\n", ref_id);
		}
	}

	if (batch_rule_add(h, NFT_COMPAT_RULE_INSERT, r) < 0) {
		nftnl_rule_free(r);
		return NULL;
	}

	if (verbose)
		h->ops->print_rule(r, 0, FMT_PRINT_RULE);

	return r;
}

int nft_rule_insert(struct nft_handle *h, const char *chain,
		    const char *table, void *data, int rulenum, bool verbose)
{
	struct nftnl_rule *r = NULL, *new_rule;
	struct nftnl_chain *c;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_xt_builtin_init(h, table);

	nft_fn = nft_rule_insert;

	c = nft_chain_find(h, table, chain);
	if (!c) {
		errno = ENOENT;
		goto err;
	}

	if (rulenum > 0) {
		r = nft_rule_find(h, c, data, rulenum);
		if (r == NULL) {
			/* special case: iptables allows to insert into
			 * rule_count + 1 position.
			 */
			r = nft_rule_find(h, c, data, rulenum - 1);
			if (r != NULL)
				return nft_rule_append(h, chain, table, data,
						       NULL, verbose);

			errno = ENOENT;
			goto err;
		}
	}

	new_rule = nft_rule_add(h, chain, table, data, r, verbose);
	if (!new_rule)
		goto err;

	if (r)
		nftnl_chain_rule_insert_at(new_rule, r);
	else
		nftnl_chain_rule_add(new_rule, c);

	return 1;
err:
	return 0;
}

int nft_rule_delete_num(struct nft_handle *h, const char *chain,
			const char *table, int rulenum, bool verbose)
{
	int ret = 0;
	struct nftnl_chain *c;
	struct nftnl_rule *r;

	nft_fn = nft_rule_delete_num;

	c = nft_chain_find(h, table, chain);
	if (!c) {
		errno = ENOENT;
		return 0;
	}

	r = nft_rule_find(h, c, NULL, rulenum);
	if (r != NULL) {
		DEBUGP("deleting rule by number %d\n", rulenum);
		ret = __nft_rule_del(h, r);
		if (ret < 0)
			errno = ENOMEM;
	} else
		errno = ENOENT;

	return ret;
}

int nft_rule_replace(struct nft_handle *h, const char *chain,
		     const char *table, void *data, int rulenum, bool verbose)
{
	int ret = 0;
	struct nftnl_chain *c;
	struct nftnl_rule *r;

	nft_fn = nft_rule_replace;

	c = nft_chain_find(h, table, chain);
	if (!c) {
		errno = ENOENT;
		return 0;
	}

	r = nft_rule_find(h, c, data, rulenum);
	if (r != NULL) {
		DEBUGP("replacing rule with handle=%llu\n",
			(unsigned long long)
			nftnl_rule_get_u64(r, NFTNL_RULE_HANDLE));

		ret = nft_rule_append(h, chain, table, data, r, verbose);
	} else
		errno = ENOENT;

	return ret;
}

static int
__nft_rule_list(struct nft_handle *h, struct nftnl_chain *c,
		int rulenum, unsigned int format,
		void (*cb)(struct nftnl_rule *r, unsigned int num,
			   unsigned int format))
{
	struct nftnl_rule_iter *iter;
	struct nftnl_rule *r;
	int rule_ctr = 0;

	if (rulenum > 0) {
		r = nftnl_rule_lookup_byindex(c, rulenum - 1);
		if (!r)
			/* iptables-legacy returns 0 when listing for
			 * valid chain but invalid rule number
			 */
			return 1;
		cb(r, rulenum, format);
		return 1;
	}

	iter = nftnl_rule_iter_create(c);
	if (iter == NULL)
		return 0;

	r = nftnl_rule_iter_next(iter);
	while (r != NULL) {
		rule_ctr++;

		if (rulenum > 0 && rule_ctr != rulenum) {
			/* List by rule number case */
			goto next;
		}

		cb(r, rule_ctr, format);
		if (rulenum > 0)
			break;

next:
		r = nftnl_rule_iter_next(iter);
	}

	nftnl_rule_iter_destroy(iter);
	return 1;
}

static int nft_rule_count(struct nft_handle *h, struct nftnl_chain *c)
{
	struct nftnl_rule_iter *iter;
	struct nftnl_rule *r;
	int rule_ctr = 0;

	iter = nftnl_rule_iter_create(c);
	if (iter == NULL)
		return 0;

	r = nftnl_rule_iter_next(iter);
	while (r != NULL) {
		rule_ctr++;
		r = nftnl_rule_iter_next(iter);
	}

	nftnl_rule_iter_destroy(iter);
	return rule_ctr;
}

static void __nft_print_header(struct nft_handle *h,
			       const struct nft_family_ops *ops,
			       struct nftnl_chain *c, unsigned int format)
{
	const char *chain_name = nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);
	uint32_t policy = nftnl_chain_get_u32(c, NFTNL_CHAIN_POLICY);
	bool basechain = !!nftnl_chain_get(c, NFTNL_CHAIN_HOOKNUM);
	uint32_t refs = nftnl_chain_get_u32(c, NFTNL_CHAIN_USE);
	uint32_t entries = nft_rule_count(h, c);
	struct xt_counters ctrs = {
		.pcnt = nftnl_chain_get_u64(c, NFTNL_CHAIN_PACKETS),
		.bcnt = nftnl_chain_get_u64(c, NFTNL_CHAIN_BYTES),
	};

	ops->print_header(format, chain_name, policy_name[policy],
			&ctrs, basechain, refs - entries, entries);
}

int nft_rule_list(struct nft_handle *h, const char *chain, const char *table,
		  int rulenum, unsigned int format)
{
	const struct nft_family_ops *ops;
	struct nftnl_chain_list *list;
	struct nftnl_chain_list_iter *iter;
	struct nftnl_chain *c;
	bool found = false;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_xt_builtin_init(h, table);

	ops = nft_family_ops_lookup(h->family);

	if (!nft_is_table_compatible(h, table)) {
		xtables_error(OTHER_PROBLEM, "table `%s' is incompatible, use 'nft' tool.\n", table);
		return 0;
	}

	list = nft_chain_list_get(h, table);
	if (!list)
		return 0;

	if (chain) {
		c = nftnl_chain_list_lookup_byname(list, chain);
		if (!c)
			return 0;

		if (!rulenum) {
			if (ops->print_table_header)
				ops->print_table_header(table);
			__nft_print_header(h, ops, c, format);
		}
		__nft_rule_list(h, c, rulenum, format, ops->print_rule);
		return 1;
	}

	iter = nftnl_chain_list_iter_create(list);
	if (iter == NULL)
		return 0;

	if (ops->print_table_header)
		ops->print_table_header(table);

	c = nftnl_chain_list_iter_next(iter);
	while (c != NULL) {
		if (found)
			printf("\n");

		__nft_print_header(h, ops, c, format);
		__nft_rule_list(h, c, rulenum, format, ops->print_rule);

		found = true;
		c = nftnl_chain_list_iter_next(iter);
	}
	nftnl_chain_list_iter_destroy(iter);
	return 1;
}

static void
list_save(struct nftnl_rule *r, unsigned int num, unsigned int format)
{
	nft_rule_print_save(r, NFT_RULE_APPEND, format);
}

static int __nftnl_rule_list_chain_save(struct nftnl_chain *c, void *data)
{
	const char *chain_name = nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);
	uint32_t policy = nftnl_chain_get_u32(c, NFTNL_CHAIN_POLICY);
	int *counters = data;

	if (!nft_chain_builtin(c)) {
		printf("-N %s\n", chain_name);
		return 0;
	}

	/* this is a base chain */

	printf("-P %s %s", chain_name, policy_name[policy]);
	if (*counters)
		printf(" -c %"PRIu64" %"PRIu64,
		       nftnl_chain_get_u64(c, NFTNL_CHAIN_PACKETS),
		       nftnl_chain_get_u64(c, NFTNL_CHAIN_BYTES));
	printf("\n");
	return 0;
}

static int
nftnl_rule_list_chain_save(struct nft_handle *h, const char *chain,
			   struct nftnl_chain_list *list, int counters)
{
	struct nftnl_chain *c;

	if (chain) {
		c = nftnl_chain_list_lookup_byname(list, chain);
		if (!c)
			return 0;

		__nftnl_rule_list_chain_save(c, &counters);
		return 1;
	}

	nftnl_chain_list_foreach(list, __nftnl_rule_list_chain_save, &counters);
	return 1;
}

int nft_rule_list_save(struct nft_handle *h, const char *chain,
		       const char *table, int rulenum, int counters)
{
	struct nftnl_chain_list *list;
	struct nftnl_chain_list_iter *iter;
	unsigned int format = 0;
	struct nftnl_chain *c;
	int ret = 0;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_xt_builtin_init(h, table);

	if (!nft_is_table_compatible(h, table)) {
		xtables_error(OTHER_PROBLEM, "table `%s' is incompatible, use 'nft' tool.\n", table);
		return 0;
	}

	list = nft_chain_list_get(h, table);
	if (!list)
		return 0;

	/* Dump policies and custom chains first */
	if (!rulenum)
		nftnl_rule_list_chain_save(h, chain, list, counters);

	if (counters < 0)
		format = FMT_C_COUNTS;
	else if (counters == 0)
		format = FMT_NOCOUNTS;

	if (chain) {
		c = nftnl_chain_list_lookup_byname(list, chain);
		if (!c)
			return 0;

		return __nft_rule_list(h, c, rulenum, format, list_save);
	}

	/* Now dump out rules in this table */
	iter = nftnl_chain_list_iter_create(list);
	if (iter == NULL)
		return 0;

	c = nftnl_chain_list_iter_next(iter);
	while (c != NULL) {
		ret = __nft_rule_list(h, c, rulenum, format, list_save);
		c = nftnl_chain_list_iter_next(iter);
	}
	nftnl_chain_list_iter_destroy(iter);
	return ret;
}

int nft_rule_zero_counters(struct nft_handle *h, const char *chain,
			   const char *table, int rulenum)
{
	struct iptables_command_state cs = {};
	struct nftnl_chain *c;
	struct nftnl_rule *r;
	int ret = 0;

	nft_fn = nft_rule_delete;

	c = nft_chain_find(h, table, chain);
	if (!c)
		return 0;

	r = nft_rule_find(h, c, NULL, rulenum);
	if (r == NULL) {
		errno = ENOENT;
		ret = 1;
		goto error;
	}

	nft_rule_to_iptables_command_state(r, &cs);

	cs.counters.pcnt = cs.counters.bcnt = 0;

	ret =  nft_rule_append(h, chain, table, &cs, r, false);

error:
	return ret;
}

static void nft_compat_table_batch_add(struct nft_handle *h, uint16_t type,
				       uint16_t flags, uint32_t seq,
				       struct nftnl_table *table)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_table_nlmsg_build_hdr(nftnl_batch_buffer(h->batch),
					type, h->family, flags, seq);
	nftnl_table_nlmsg_build_payload(nlh, table);
}

static void nft_compat_chain_batch_add(struct nft_handle *h, uint16_t type,
				       uint16_t flags, uint32_t seq,
				       struct nftnl_chain *chain)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_chain_nlmsg_build_hdr(nftnl_batch_buffer(h->batch),
					type, h->family, flags, seq);
	nftnl_chain_nlmsg_build_payload(nlh, chain);
	nft_chain_print_debug(chain, nlh);
}

static void nft_compat_rule_batch_add(struct nft_handle *h, uint16_t type,
				      uint16_t flags, uint32_t seq,
				      struct nftnl_rule *rule)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_rule_nlmsg_build_hdr(nftnl_batch_buffer(h->batch),
				       type, h->family, flags, seq);
	nftnl_rule_nlmsg_build_payload(nlh, rule);
	nft_rule_print_debug(rule, nlh);
}

static void batch_obj_del(struct nft_handle *h, struct obj_update *o)
{
	switch (o->type) {
	case NFT_COMPAT_TABLE_ADD:
	case NFT_COMPAT_TABLE_FLUSH:
		nftnl_table_free(o->table);
		break;
	case NFT_COMPAT_CHAIN_ZERO:
	case NFT_COMPAT_CHAIN_USER_ADD:
	case NFT_COMPAT_CHAIN_ADD:
		break;
	case NFT_COMPAT_CHAIN_USER_DEL:
	case NFT_COMPAT_CHAIN_USER_FLUSH:
	case NFT_COMPAT_CHAIN_UPDATE:
	case NFT_COMPAT_CHAIN_RENAME:
		nftnl_chain_free(o->chain);
		break;
	case NFT_COMPAT_RULE_APPEND:
	case NFT_COMPAT_RULE_INSERT:
	case NFT_COMPAT_RULE_REPLACE:
	case NFT_COMPAT_RULE_DELETE:
		break;
	case NFT_COMPAT_RULE_FLUSH:
		nftnl_rule_free(o->rule);
		break;
	}
	h->obj_list_num--;
	list_del(&o->head);
	free(o);
}

static int nft_action(struct nft_handle *h, int action)
{
	struct obj_update *n, *tmp;
	struct mnl_err *err, *ne;
	unsigned int buflen, i, len;
	bool show_errors = true;
	char errmsg[1024];
	uint32_t seq = 1;
	int ret = 0;

	h->batch = mnl_batch_init();

	mnl_batch_begin(h->batch, seq++);

	list_for_each_entry(n, &h->obj_list, head) {
		n->seq = seq++;
		switch (n->type) {
		case NFT_COMPAT_TABLE_ADD:
			nft_compat_table_batch_add(h, NFT_MSG_NEWTABLE,
						   NLM_F_CREATE, n->seq,
						   n->table);
			break;
		case NFT_COMPAT_TABLE_FLUSH:
			nft_compat_table_batch_add(h, NFT_MSG_DELTABLE,
						   0,
						   n->seq, n->table);
			break;
		case NFT_COMPAT_CHAIN_ADD:
		case NFT_COMPAT_CHAIN_ZERO:
			nft_compat_chain_batch_add(h, NFT_MSG_NEWCHAIN,
						   NLM_F_CREATE, n->seq,
						   n->chain);
			break;
		case NFT_COMPAT_CHAIN_USER_ADD:
			nft_compat_chain_batch_add(h, NFT_MSG_NEWCHAIN,
						   NLM_F_EXCL, n->seq,
						   n->chain);
			break;
		case NFT_COMPAT_CHAIN_USER_DEL:
			nft_compat_chain_batch_add(h, NFT_MSG_DELCHAIN,
						   NLM_F_NONREC, n->seq,
						   n->chain);
			break;
		case NFT_COMPAT_CHAIN_USER_FLUSH:
			nft_compat_chain_batch_add(h, NFT_MSG_DELCHAIN,
						   0, n->seq,
						   n->chain);
			break;
		case NFT_COMPAT_CHAIN_UPDATE:
			nft_compat_chain_batch_add(h, NFT_MSG_NEWCHAIN,
						   h->restore ?
						     NLM_F_CREATE : 0,
						   n->seq, n->chain);
			break;
		case NFT_COMPAT_CHAIN_RENAME:
			nft_compat_chain_batch_add(h, NFT_MSG_NEWCHAIN, 0,
						   n->seq, n->chain);
			break;
		case NFT_COMPAT_RULE_APPEND:
			nft_compat_rule_batch_add(h, NFT_MSG_NEWRULE,
						  NLM_F_CREATE | NLM_F_APPEND,
						  n->seq, n->rule);
			break;
		case NFT_COMPAT_RULE_INSERT:
			nft_compat_rule_batch_add(h, NFT_MSG_NEWRULE,
						  NLM_F_CREATE, n->seq,
						  n->rule);
			break;
		case NFT_COMPAT_RULE_REPLACE:
			nft_compat_rule_batch_add(h, NFT_MSG_NEWRULE,
						  NLM_F_CREATE | NLM_F_REPLACE,
						  n->seq, n->rule);
			break;
		case NFT_COMPAT_RULE_DELETE:
		case NFT_COMPAT_RULE_FLUSH:
			nft_compat_rule_batch_add(h, NFT_MSG_DELRULE, 0,
						  n->seq, n->rule);
			break;
		}

		mnl_nft_batch_continue(h->batch);
	}

	switch (action) {
	case NFT_COMPAT_COMMIT:
		mnl_batch_end(h->batch, seq++);
		break;
	case NFT_COMPAT_ABORT:
		break;
	}

	ret = mnl_batch_talk(h->nl, h->batch, &h->err_list);

	i = 0;
	buflen = sizeof(errmsg);

	list_for_each_entry_safe(n, tmp, &h->obj_list, head) {
		list_for_each_entry_safe(err, ne, &h->err_list, head) {
			if (err->seqnum > n->seq)
				break;

			if (err->seqnum == n->seq && show_errors) {
				if (n->error.lineno == 0)
					show_errors = false;
				len = mnl_append_error(h, n, err, errmsg + i, buflen);
				if (len > 0 && len <= buflen) {
					buflen -= len;
					i += len;
				}
			}
			mnl_err_list_free(err);
		}
		batch_obj_del(h, n);
	}

	mnl_batch_reset(h->batch);

	if (i)
		xtables_error(RESOURCE_PROBLEM, "%s", errmsg);

	return ret == 0 ? 1 : 0;
}

int nft_commit(struct nft_handle *h)
{
	return nft_action(h, NFT_COMPAT_COMMIT);
}

int nft_abort(struct nft_handle *h)
{
	return nft_action(h, NFT_COMPAT_ABORT);
}

int nft_compatible_revision(const char *name, uint8_t rev, int opt)
{
	struct mnl_socket *nl;
	char buf[16536];
	struct nlmsghdr *nlh;
	uint32_t portid, seq, type = 0;
	uint32_t pf = AF_INET;
	int ret = 0;

	switch (opt) {
	case IPT_SO_GET_REVISION_MATCH:
		break;
	case IP6T_SO_GET_REVISION_MATCH:
		pf = AF_INET6;
		break;
	case IPT_SO_GET_REVISION_TARGET:
		type = 1;
		break;
	case IP6T_SO_GET_REVISION_TARGET:
		type = 1;
		pf = AF_INET6;
		break;
	default:
		/* No revision support (arp, ebtables), assume latest version ok */
		return 1;
	}

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_NFT_COMPAT << 8) | NFNL_MSG_COMPAT_GET;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = pf;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = 0;

	mnl_attr_put_strz(nlh, NFTA_COMPAT_NAME, name);
	mnl_attr_put_u32(nlh, NFTA_COMPAT_REV, htonl(rev));
	mnl_attr_put_u32(nlh, NFTA_COMPAT_TYPE, htonl(type));

	DEBUGP("requesting `%s' rev=%d type=%d via nft_compat\n",
		name, rev, type);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL)
		return 0;

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		goto err;

	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		goto err;

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret == -1)
		goto err;

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	if (ret == -1)
		goto err;

err:
	mnl_socket_close(nl);

	return ret < 0 ? 0 : 1;
}

/* Translates errno numbers into more human-readable form than strerror. */
const char *nft_strerror(int err)
{
	unsigned int i;
	static struct table_struct {
		void *fn;
		int err;
		const char *message;
	} table[] =
	  {
	    { nft_chain_user_del, ENOTEMPTY, "Chain is not empty" },
	    { nft_chain_user_del, EINVAL, "Can't delete built-in chain" },
	    { nft_chain_user_del, EBUSY, "Directory not empty" },
	    { nft_chain_user_del, EMLINK,
	      "Can't delete chain with references left" },
	    { nft_chain_user_add, EEXIST, "Chain already exists" },
	    { nft_rule_insert, ENOENT, "Index of insertion too big" },
	    { nft_rule_check, ENOENT, "Bad rule (does a matching rule exist in that chain?)" },
	    { nft_rule_replace, ENOENT, "Index of replacement too big" },
	    { nft_rule_delete_num, ENOENT, "Index of deletion too big" },
/*	    { TC_READ_COUNTER, E2BIG, "Index of counter too big" },
	    { TC_ZERO_COUNTER, E2BIG, "Index of counter too big" }, */
	    /* ENOENT for DELETE probably means no matching rule */
	    { nft_rule_delete, ENOENT,
	      "Bad rule (does a matching rule exist in that chain?)" },
	    { nft_chain_set, ENOENT, "Bad built-in chain name" },
	    { nft_chain_set, EINVAL, "Bad policy name" },
	    { nft_chain_set, ENXIO, "Bad table name" },
	    { NULL, ELOOP, "Loop found in table" },
	    { NULL, EPERM, "Permission denied (you must be root)" },
	    { NULL, 0, "Incompatible with this kernel" },
	    { NULL, ENOPROTOOPT, "iptables who? (do you need to insmod?)" },
	    { NULL, ENOSYS, "Will be implemented real soon.  I promise ;)" },
	    { NULL, ENOMEM, "Memory allocation problem" },
	    { NULL, ENOENT, "No chain/target/match by that name" },
	  };

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((!table[i].fn || table[i].fn == nft_fn)
		    && table[i].err == err)
			return table[i].message;
	}

	return strerror(err);
}

static void xtables_config_perror(uint32_t flags, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);

	if (flags & NFT_LOAD_VERBOSE)
		vfprintf(stderr, fmt, args);

	va_end(args);
}

static int __nft_xtables_config_load(struct nft_handle *h, const char *filename,
				     uint32_t flags)
{
	struct nftnl_table_list *table_list = NULL;
	struct nftnl_chain_list *chain_list = NULL;
	struct nftnl_table_list_iter *titer = NULL;
	struct nftnl_chain_list_iter *citer = NULL;
	struct nftnl_table *table;
	struct nftnl_chain *chain;
	uint32_t table_family, chain_family;
	bool found = false;

	table_list = nftnl_table_list_alloc();
	chain_list = nftnl_chain_list_alloc();

	if (xtables_config_parse(filename, table_list, chain_list) < 0) {
		if (errno == ENOENT) {
			xtables_config_perror(flags,
				"configuration file `%s' does not exists\n",
				filename);
		} else {
			xtables_config_perror(flags,
				"Fatal error parsing config file: %s\n",
				 strerror(errno));
		}
		goto err;
	}

	/* Stage 1) create tables */
	titer = nftnl_table_list_iter_create(table_list);
	while ((table = nftnl_table_list_iter_next(titer)) != NULL) {
		table_family = nftnl_table_get_u32(table,
						      NFTNL_TABLE_FAMILY);
		if (h->family != table_family)
			continue;

		found = true;

		if (batch_table_add(h, NFT_COMPAT_TABLE_ADD, table) < 0) {
			if (errno == EEXIST) {
				xtables_config_perror(flags,
					"table `%s' already exists, skipping\n",
					(char *)nftnl_table_get(table, NFTNL_TABLE_NAME));
			} else {
				xtables_config_perror(flags,
					"table `%s' cannot be create, reason `%s'. Exitting\n",
					(char *)nftnl_table_get(table, NFTNL_TABLE_NAME),
					strerror(errno));
				goto err;
			}
			continue;
		}
		xtables_config_perror(flags, "table `%s' has been created\n",
			(char *)nftnl_table_get(table, NFTNL_TABLE_NAME));
	}
	nftnl_table_list_iter_destroy(titer);
	nftnl_table_list_free(table_list);

	if (!found)
		goto err;

	/* Stage 2) create chains */
	citer = nftnl_chain_list_iter_create(chain_list);
	while ((chain = nftnl_chain_list_iter_next(citer)) != NULL) {
		chain_family = nftnl_chain_get_u32(chain,
						      NFTNL_CHAIN_TABLE);
		if (h->family != chain_family)
			continue;

		if (batch_chain_add(h, NFT_COMPAT_CHAIN_ADD, chain) < 0) {
			if (errno == EEXIST) {
				xtables_config_perror(flags,
					"chain `%s' already exists in table `%s', skipping\n",
					(char *)nftnl_chain_get(chain, NFTNL_CHAIN_NAME),
					(char *)nftnl_chain_get(chain, NFTNL_CHAIN_TABLE));
			} else {
				xtables_config_perror(flags,
					"chain `%s' cannot be create, reason `%s'. Exitting\n",
					(char *)nftnl_chain_get(chain, NFTNL_CHAIN_NAME),
					strerror(errno));
				goto err;
			}
			continue;
		}

		xtables_config_perror(flags,
			"chain `%s' in table `%s' has been created\n",
			(char *)nftnl_chain_get(chain, NFTNL_CHAIN_NAME),
			(char *)nftnl_chain_get(chain, NFTNL_CHAIN_TABLE));
	}
	nftnl_chain_list_iter_destroy(citer);
	nftnl_chain_list_free(chain_list);

	h->config_done = 1;

	return 0;

err:
	nftnl_table_list_free(table_list);
	nftnl_chain_list_free(chain_list);

	if (titer != NULL)
		nftnl_table_list_iter_destroy(titer);
	if (citer != NULL)
		nftnl_chain_list_iter_destroy(citer);

	h->config_done = -1;

	return -1;
}

int nft_xtables_config_load(struct nft_handle *h, const char *filename,
			    uint32_t flags)
{
	if (!h->config_done)
		return __nft_xtables_config_load(h, filename, flags);

	return h->config_done;
}

struct chain_zero_data {
	struct nft_handle	*handle;
	bool			verbose;
};

static int __nft_chain_zero_counters(struct nftnl_chain *c, void *data)
{
	struct chain_zero_data *d = data;
	struct nft_handle *h = d->handle;
	struct nftnl_rule_iter *iter;
	struct nftnl_rule *r;
	int ret = 0;

	if (d->verbose)
		fprintf(stdout, "Zeroing chain `%s'\n",
			nftnl_chain_get_str(c, NFTNL_CHAIN_NAME));

	if (nftnl_chain_is_set(c, NFTNL_CHAIN_HOOKNUM)) {
		/* zero base chain counters. */
		nftnl_chain_set_u64(c, NFTNL_CHAIN_PACKETS, 0);
		nftnl_chain_set_u64(c, NFTNL_CHAIN_BYTES, 0);
		nftnl_chain_unset(c, NFTNL_CHAIN_HANDLE);
		ret = batch_chain_add(h, NFT_COMPAT_CHAIN_ZERO, c);
		if (ret)
			return -1;
	}

	iter = nftnl_rule_iter_create(c);
	if (iter == NULL)
		return -1;

	r = nftnl_rule_iter_next(iter);
	while (r != NULL) {
		struct nftnl_expr_iter *ei;
		struct nftnl_expr *e;
		bool zero_needed;

		ei = nftnl_expr_iter_create(r);
		if (!ei)
			break;

		e = nftnl_expr_iter_next(ei);
	        zero_needed = false;
		while (e != NULL) {
			const char *en = nftnl_expr_get_str(e, NFTNL_EXPR_NAME);

			if (strcmp(en, "counter") == 0 && (
			    nftnl_expr_get_u64(e, NFTNL_EXPR_CTR_PACKETS) ||
			    nftnl_expr_get_u64(e, NFTNL_EXPR_CTR_BYTES))) {
				nftnl_expr_set_u64(e, NFTNL_EXPR_CTR_PACKETS, 0);
				nftnl_expr_set_u64(e, NFTNL_EXPR_CTR_BYTES, 0);
				zero_needed = true;
			}

			e = nftnl_expr_iter_next(ei);
		}

		nftnl_expr_iter_destroy(ei);

		if (zero_needed) {
			/*
			 * Unset RULE_POSITION for older kernels, we want to replace
			 * rule based on its handle only.
			 */
			nftnl_rule_unset(r, NFTNL_RULE_POSITION);
			batch_rule_add(h, NFT_COMPAT_RULE_REPLACE, r);
		}
		r = nftnl_rule_iter_next(iter);
	}

	nftnl_rule_iter_destroy(iter);
	return 0;
}

int nft_chain_zero_counters(struct nft_handle *h, const char *chain,
			    const char *table, bool verbose)
{
	struct nftnl_chain_list *list;
	struct chain_zero_data d = {
		.handle = h,
		.verbose = verbose,
	};
	struct nftnl_chain *c;
	int ret = 0;

	list = nft_chain_list_get(h, table);
	if (list == NULL)
		goto err;

	if (chain) {
		c = nftnl_chain_list_lookup_byname(list, chain);
		if (!c)
			return 0;

		ret = __nft_chain_zero_counters(c, &d);
		goto err;
	}

	ret = nftnl_chain_list_foreach(list, __nft_chain_zero_counters, &d);
err:
	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

uint32_t nft_invflags2cmp(uint32_t invflags, uint32_t flag)
{
	if (invflags & flag)
		return NFT_CMP_NEQ;

	return NFT_CMP_EQ;
}

#define NFT_COMPAT_EXPR_MAX     8

static const char *supported_exprs[NFT_COMPAT_EXPR_MAX] = {
	"match",
	"target",
	"payload",
	"meta",
	"cmp",
	"bitwise",
	"counter",
	"immediate"
};


static int nft_is_expr_compatible(struct nftnl_expr *expr, void *data)
{
	const char *name = nftnl_expr_get_str(expr, NFTNL_EXPR_NAME);
	int i;

	for (i = 0; i < NFT_COMPAT_EXPR_MAX; i++) {
		if (strcmp(supported_exprs[i], name) == 0)
			return 0;
	}

	if (!strcmp(name, "limit") &&
	    nftnl_expr_get_u32(expr, NFTNL_EXPR_LIMIT_TYPE) == NFT_LIMIT_PKTS &&
	    nftnl_expr_get_u32(expr, NFTNL_EXPR_LIMIT_FLAGS) == 0)
		return 0;

	return -1;
}

static int nft_is_rule_compatible(struct nftnl_rule *rule, void *data)
{
	return nftnl_expr_foreach(rule, nft_is_expr_compatible, NULL);
}

static int nft_is_chain_compatible(struct nftnl_chain *c, void *data)
{
	const struct builtin_table *table;
	const struct builtin_chain *chain;
	const char *tname, *cname, *type;
	struct nft_handle *h = data;
	enum nf_inet_hooks hook;
	int prio;

	if (nftnl_rule_foreach(c, nft_is_rule_compatible, NULL))
		return -1;

	if (!nft_chain_builtin(c))
		return 0;

	tname = nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE);
	table = nft_table_builtin_find(h, tname);
	if (!table)
		return -1;

	cname = nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);
	chain = nft_chain_builtin_find(table, cname);
	if (!chain)
		return -1;

	type = nftnl_chain_get_str(c, NFTNL_CHAIN_TYPE);
	prio = nftnl_chain_get_u32(c, NFTNL_CHAIN_PRIO);
	hook = nftnl_chain_get_u32(c, NFTNL_CHAIN_HOOKNUM);
	if (strcmp(type, chain->type) ||
	    prio != chain->prio ||
	    hook != chain->hook)
		return -1;

	return 0;
}

bool nft_is_table_compatible(struct nft_handle *h, const char *tablename)
{
	struct nftnl_chain_list *clist;

	clist = nft_chain_list_get(h, tablename);
	if (clist == NULL)
		return false;

	if (nftnl_chain_list_foreach(clist, nft_is_chain_compatible, h))
		return false;

	return true;
}
