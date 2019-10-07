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

#include <assert.h>
#include <errno.h>
#include <xtables.h>

#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/gen.h>
#include <libnftnl/table.h>

#include "nft.h"
#include "nft-cache.h"

static int genid_cb(const struct nlmsghdr *nlh, void *data)
{
	uint32_t *genid = data;
	struct nftnl_gen *gen;

	gen = nftnl_gen_alloc();
	if (!gen)
		return MNL_CB_ERROR;

	if (nftnl_gen_nlmsg_parse(nlh, gen) < 0)
		goto out;

	*genid = nftnl_gen_get_u32(gen, NFTNL_GEN_ID);

	nftnl_gen_free(gen);
	return MNL_CB_STOP;
out:
	nftnl_gen_free(gen);
	return MNL_CB_ERROR;
}

static void mnl_genid_get(struct nft_handle *h, uint32_t *genid)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	int ret;

	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETGEN, 0, 0, h->seq);
	ret = mnl_talk(h, nlh, genid_cb, genid);
	if (ret == 0)
		return;

	xtables_error(RESOURCE_PROBLEM,
		      "Could not fetch rule set generation id: %s\n", nft_strerror(errno));
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

static int fetch_table_cache(struct nft_handle *h)
{
	char buf[16536];
	struct nlmsghdr *nlh;
	struct nftnl_table_list *list;
	int ret;

	if (h->cache->tables)
		return 0;

	list = nftnl_table_list_alloc();
	if (list == NULL)
		return 0;

	nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE, h->family,
					NLM_F_DUMP, h->seq);

	ret = mnl_talk(h, nlh, nftnl_table_list_cb, list);
	if (ret < 0 && errno == EINTR)
		assert(nft_restart(h) >= 0);

	h->cache->tables = list;

	return 1;
}

static int nftnl_chain_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_handle *h = data;
	const struct builtin_table *t;
	struct nftnl_chain_list *list;
	struct nftnl_chain *c;
	const char *cname;

	c = nftnl_chain_alloc();
	if (c == NULL)
		goto err;

	if (nftnl_chain_nlmsg_parse(nlh, c) < 0)
		goto out;

	t = nft_table_builtin_find(h,
			nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE));
	if (!t)
		goto out;

	list = h->cache->table[t->type].chains;
	cname = nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);

	if (nftnl_chain_list_lookup_byname(list, cname))
		goto out;

	nftnl_chain_list_add_tail(c, list);

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

	for (i = 0; i < NFT_TABLE_MAX; i++) {
		enum nft_table_type type = h->tables[i].type;

		if (!h->tables[i].name)
			continue;

		if (h->cache->table[type].chains)
			continue;

		h->cache->table[type].chains = nftnl_chain_list_alloc();
		if (!h->cache->table[type].chains)
			return -1;
	}

	nlh = nftnl_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN, h->family,
					NLM_F_DUMP, h->seq);

	ret = mnl_talk(h, nlh, nftnl_chain_list_cb, h);
	if (ret < 0 && errno == EINTR)
		assert(nft_restart(h) >= 0);

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

	if (nftnl_rule_lookup_byindex(c, 0))
		return 0;

	rule = nftnl_rule_alloc();
	if (!rule)
		return -1;

	nftnl_rule_set_str(rule, NFTNL_RULE_TABLE,
			   nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE));
	nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN,
			   nftnl_chain_get_str(c, NFTNL_CHAIN_NAME));

	nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, h->family,
					NLM_F_DUMP, h->seq);
	nftnl_rule_nlmsg_build_payload(nlh, rule);

	ret = mnl_talk(h, nlh, nftnl_rule_list_cb, c);
	if (ret < 0 && errno == EINTR)
		assert(nft_restart(h) >= 0);

	nftnl_rule_free(rule);

	if (h->family == NFPROTO_BRIDGE)
		nft_bridge_chain_postprocess(h, c);

	return 0;
}

static int fetch_rule_cache(struct nft_handle *h)
{
	int i;

	for (i = 0; i < NFT_TABLE_MAX; i++) {
		enum nft_table_type type = h->tables[i].type;

		if (!h->tables[i].name)
			continue;

		if (nftnl_chain_list_foreach(h->cache->table[type].chains,
					     nft_rule_list_update, h))
			return -1;
	}
	return 0;
}

static void __nft_build_cache(struct nft_handle *h, enum nft_cache_level level)
{
	uint32_t genid_start, genid_stop;

	if (level <= h->cache_level)
		return;
retry:
	mnl_genid_get(h, &genid_start);

	if (h->cache_level && genid_start != h->nft_genid)
		flush_chain_cache(h, NULL);

	switch (h->cache_level) {
	case NFT_CL_NONE:
		fetch_table_cache(h);
		if (level == NFT_CL_TABLES)
			break;
		/* fall through */
	case NFT_CL_TABLES:
		fetch_chain_cache(h);
		if (level == NFT_CL_CHAINS)
			break;
		/* fall through */
	case NFT_CL_CHAINS:
		fetch_rule_cache(h);
		if (level == NFT_CL_RULES)
			break;
		/* fall through */
	case NFT_CL_RULES:
		break;
	}

	mnl_genid_get(h, &genid_stop);
	if (genid_start != genid_stop) {
		flush_chain_cache(h, NULL);
		goto retry;
	}

	h->cache_level = level;
	h->nft_genid = genid_start;
}

void nft_build_cache(struct nft_handle *h)
{
	if (h->cache_level < NFT_CL_RULES)
		__nft_build_cache(h, NFT_CL_RULES);
}

void nft_fake_cache(struct nft_handle *h)
{
	int i;

	fetch_table_cache(h);
	for (i = 0; i < NFT_TABLE_MAX; i++) {
		enum nft_table_type type = h->tables[i].type;

		if (!h->tables[i].name)
			continue;

		h->cache->table[type].chains = nftnl_chain_list_alloc();
	}
	h->cache_level = NFT_CL_RULES;
	mnl_genid_get(h, &h->nft_genid);
}

static void __nft_flush_cache(struct nft_handle *h)
{
	if (!h->cache_index) {
		h->cache_index++;
		h->cache = &h->__cache[h->cache_index];
	} else {
		flush_chain_cache(h, NULL);
	}
}

static int __flush_rule_cache(struct nftnl_rule *r, void *data)
{
	nftnl_rule_list_del(r);
	nftnl_rule_free(r);

	return 0;
}

void flush_rule_cache(struct nftnl_chain *c)
{
	nftnl_rule_foreach(c, __flush_rule_cache, NULL);
}

static int __flush_chain_cache(struct nftnl_chain *c, void *data)
{
	nftnl_chain_list_del(c);
	nftnl_chain_free(c);

	return 0;
}

static int flush_cache(struct nft_handle *h, struct nft_cache *c,
		       const char *tablename)
{
	const struct builtin_table *table;
	int i;

	if (tablename) {
		table = nft_table_builtin_find(h, tablename);
		if (!table || !c->table[table->type].chains)
			return 0;
		nftnl_chain_list_foreach(c->table[table->type].chains,
					 __flush_chain_cache, NULL);
		return 0;
	}

	for (i = 0; i < NFT_TABLE_MAX; i++) {
		if (h->tables[i].name == NULL)
			continue;

		if (!c->table[i].chains)
			continue;

		nftnl_chain_list_free(c->table[i].chains);
		c->table[i].chains = NULL;
	}
	nftnl_table_list_free(c->tables);
	c->tables = NULL;

	return 1;
}

void flush_chain_cache(struct nft_handle *h, const char *tablename)
{
	if (!h->cache_level)
		return;

	if (flush_cache(h, h->cache, tablename))
		h->cache_level = NFT_CL_NONE;
}

void nft_rebuild_cache(struct nft_handle *h)
{
	enum nft_cache_level level = h->cache_level;

	if (h->cache_level)
		__nft_flush_cache(h);

	h->cache_level = NFT_CL_NONE;
	__nft_build_cache(h, level);
}

void nft_release_cache(struct nft_handle *h)
{
	if (h->cache_index)
		flush_cache(h, &h->__cache[0], NULL);
}

struct nftnl_table_list *nftnl_table_list_get(struct nft_handle *h)
{
	__nft_build_cache(h, NFT_CL_TABLES);

	return h->cache->tables;
}

struct nftnl_chain_list *nft_chain_list_get(struct nft_handle *h,
					    const char *table)
{
	const struct builtin_table *t;

	t = nft_table_builtin_find(h, table);
	if (!t)
		return NULL;

	__nft_build_cache(h, NFT_CL_CHAINS);

	return h->cache->table[t->type].chains;
}

