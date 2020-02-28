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
#include <string.h>
#include <xtables.h>

#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/gen.h>
#include <libnftnl/set.h>
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

struct nftnl_chain_list_cb_data {
	struct nft_handle *h;
	const struct builtin_table *t;
};

static int nftnl_chain_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_chain_list_cb_data *d = data;
	const struct builtin_table *t = d->t;
	struct nftnl_chain_list *list;
	struct nft_handle *h = d->h;
	const char *tname, *cname;
	struct nftnl_chain *c;

	c = nftnl_chain_alloc();
	if (c == NULL)
		goto err;

	if (nftnl_chain_nlmsg_parse(nlh, c) < 0)
		goto out;

	tname = nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE);

	if (!t) {
		t = nft_table_builtin_find(h, tname);
		if (!t)
			goto out;
	} else if (strcmp(t->name, tname)) {
		goto out;
	}

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

struct nftnl_set_list_cb_data {
	struct nft_handle *h;
	const struct builtin_table *t;
};

static int nftnl_set_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_set_list_cb_data *d = data;
	const struct builtin_table *t = d->t;
	struct nftnl_set_list *list;
	struct nft_handle *h = d->h;
	const char *tname, *sname;
	struct nftnl_set *s;

	s = nftnl_set_alloc();
	if (s == NULL)
		return MNL_CB_OK;

	if (nftnl_set_nlmsg_parse(nlh, s) < 0)
		goto out_free;

	tname = nftnl_set_get_str(s, NFTNL_SET_TABLE);

	if (!t)
		t = nft_table_builtin_find(h, tname);
	else if (strcmp(t->name, tname))
		goto out_free;

	if (!t)
		goto out_free;

	list = h->cache->table[t->type].sets;
	sname = nftnl_set_get_str(s, NFTNL_SET_NAME);

	if (nftnl_set_list_lookup_byname(list, sname))
		goto out_free;

	nftnl_set_list_add_tail(s, list);

	return MNL_CB_OK;
out_free:
	nftnl_set_free(s);
	return MNL_CB_OK;
}

static int set_elem_cb(const struct nlmsghdr *nlh, void *data)
{
	return nftnl_set_elems_nlmsg_parse(nlh, data) ? -1 : MNL_CB_OK;
}

static bool set_has_elements(struct nftnl_set *s)
{
	struct nftnl_set_elems_iter *iter;
	bool ret = false;

	iter = nftnl_set_elems_iter_create(s);
	if (iter) {
		ret = !!nftnl_set_elems_iter_cur(iter);
		nftnl_set_elems_iter_destroy(iter);
	}
	return ret;
}

static int set_fetch_elem_cb(struct nftnl_set *s, void *data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nft_handle *h = data;
	struct nlmsghdr *nlh;

	if (set_has_elements(s))
		return 0;

	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETSETELEM, h->family,
				    NLM_F_DUMP, h->seq);
	nftnl_set_elems_nlmsg_build_payload(nlh, s);

	return mnl_talk(h, nlh, set_elem_cb, s);
}

static int fetch_set_cache(struct nft_handle *h,
			   const struct builtin_table *t, const char *set)
{
	struct nftnl_set_list_cb_data d = {
		.h = h,
		.t = t,
	};
	struct nlmsghdr *nlh;
	char buf[16536];
	int i, ret;

	if (!t) {
		for (i = 0; i < NFT_TABLE_MAX; i++) {
			enum nft_table_type type = h->tables[i].type;

			if (!h->tables[i].name)
				continue;

			h->cache->table[type].sets = nftnl_set_list_alloc();
			if (!h->cache->table[type].sets)
				return -1;
		}
	} else if (!h->cache->table[t->type].sets) {
		h->cache->table[t->type].sets = nftnl_set_list_alloc();
	}

	if (t && set) {
		struct nftnl_set *s = nftnl_set_alloc();

		if (!s)
			return -1;

		nlh = nftnl_set_nlmsg_build_hdr(buf, NFT_MSG_GETSET, h->family,
						NLM_F_ACK, h->seq);
		nftnl_set_set_str(s, NFTNL_SET_TABLE, t->name);
		nftnl_set_set_str(s, NFTNL_SET_NAME, set);
		nftnl_set_nlmsg_build_payload(nlh, s);
		nftnl_set_free(s);
	} else {
		nlh = nftnl_set_nlmsg_build_hdr(buf, NFT_MSG_GETSET, h->family,
						NLM_F_DUMP, h->seq);
	}

	ret = mnl_talk(h, nlh, nftnl_set_list_cb, &d);
	if (ret < 0 && errno == EINTR) {
		assert(nft_restart(h) >= 0);
		return ret;
	}

	if (t && set) {
		struct nftnl_set *s;

		s = nftnl_set_list_lookup_byname(h->cache->table[t->type].sets,
						 set);
		set_fetch_elem_cb(s, h);
	} else if (t) {
		nftnl_set_list_foreach(h->cache->table[t->type].sets,
				       set_fetch_elem_cb, h);
	} else {
		for (i = 0; i < NFT_TABLE_MAX; i++) {
			enum nft_table_type type = h->tables[i].type;

			if (!h->tables[i].name)
				continue;

			nftnl_set_list_foreach(h->cache->table[type].sets,
					       set_fetch_elem_cb, h);
		}
	}
	return ret;
}

static int fetch_chain_cache(struct nft_handle *h,
			     const struct builtin_table *t,
			     const char *chain)
{
	struct nftnl_chain_list_cb_data d = {
		.h = h,
		.t = t,
	};
	char buf[16536];
	struct nlmsghdr *nlh;
	int i, ret;

	if (!t) {
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
	} else if (!h->cache->table[t->type].chains) {
		h->cache->table[t->type].chains = nftnl_chain_list_alloc();
		if (!h->cache->table[t->type].chains)
			return -1;
	}

	if (t && chain) {
		struct nftnl_chain *c = nftnl_chain_alloc();

		if (!c)
			return -1;

		nlh = nftnl_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN,
						  h->family, NLM_F_ACK,
						  h->seq);
		nftnl_chain_set_str(c, NFTNL_CHAIN_TABLE, t->name);
		nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, chain);
		nftnl_chain_nlmsg_build_payload(nlh, c);
		nftnl_chain_free(c);
	} else {
		nlh = nftnl_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN,
						  h->family, NLM_F_DUMP,
						  h->seq);
	}

	ret = mnl_talk(h, nlh, nftnl_chain_list_cb, &d);
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

static int fetch_rule_cache(struct nft_handle *h,
			    const struct builtin_table *t, const char *chain)
{
	int i;

	if (t) {
		struct nftnl_chain_list *list;
		struct nftnl_chain *c;

		list = h->cache->table[t->type].chains;

		if (chain) {
			c = nftnl_chain_list_lookup_byname(list, chain);
			return nft_rule_list_update(c, h);
		}
		return nftnl_chain_list_foreach(list, nft_rule_list_update, h);
	}

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

static void
__nft_build_cache(struct nft_handle *h, enum nft_cache_level level,
		  const struct builtin_table *t, const char *set,
		  const char *chain)
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
		fetch_chain_cache(h, t, chain);
		if (level == NFT_CL_CHAINS)
			break;
		/* fall through */
	case NFT_CL_CHAINS:
		fetch_set_cache(h, t, set);
		if (level == NFT_CL_SETS)
			break;
		/* fall through */
	case NFT_CL_SETS:
		fetch_rule_cache(h, t, chain);
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

	if (!t && !chain)
		h->cache_level = level;
	else if (h->cache_level < NFT_CL_TABLES)
		h->cache_level = NFT_CL_TABLES;

	h->nft_genid = genid_start;
}

void nft_build_cache(struct nft_handle *h, struct nftnl_chain *c)
{
	const struct builtin_table *t;
	const char *table, *chain;

	if (!c)
		return __nft_build_cache(h, NFT_CL_RULES, NULL, NULL, NULL);

	table = nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE);
	chain = nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);
	t = nft_table_builtin_find(h, table);
	__nft_build_cache(h, NFT_CL_RULES, t, NULL, chain);
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

static int ____flush_rule_cache(struct nftnl_rule *r, void *data)
{
	nftnl_rule_list_del(r);
	nftnl_rule_free(r);

	return 0;
}

static int __flush_rule_cache(struct nftnl_chain *c, void *data)
{
	return nftnl_rule_foreach(c, ____flush_rule_cache, NULL);
}

int flush_rule_cache(struct nft_handle *h, const char *table,
		     struct nftnl_chain *c)
{
	const struct builtin_table *t;

	if (c)
		return __flush_rule_cache(c, NULL);

	t = nft_table_builtin_find(h, table);
	if (!t || !h->cache->table[t->type].chains)
		return 0;

	return nftnl_chain_list_foreach(h->cache->table[t->type].chains,
					__flush_rule_cache, NULL);
}

static int __flush_chain_cache(struct nftnl_chain *c, void *data)
{
	nftnl_chain_list_del(c);
	nftnl_chain_free(c);

	return 0;
}

static int __flush_set_cache(struct nftnl_set *s, void *data)
{
	nftnl_set_list_del(s);
	nftnl_set_free(s);

	return 0;
}

static int flush_cache(struct nft_handle *h, struct nft_cache *c,
		       const char *tablename)
{
	const struct builtin_table *table;
	int i;

	if (tablename) {
		table = nft_table_builtin_find(h, tablename);
		if (!table)
			return 0;
		if (c->table[table->type].chains)
			nftnl_chain_list_foreach(c->table[table->type].chains,
						 __flush_chain_cache, NULL);
		if (c->table[table->type].sets)
			nftnl_set_list_foreach(c->table[table->type].sets,
					       __flush_set_cache, NULL);
		return 0;
	}

	for (i = 0; i < NFT_TABLE_MAX; i++) {
		if (h->tables[i].name == NULL)
			continue;

		if (!c->table[i].chains)
			continue;

		nftnl_chain_list_free(c->table[i].chains);
		c->table[i].chains = NULL;
		if (c->table[i].sets)
			nftnl_set_list_free(c->table[i].sets);
		c->table[i].sets = NULL;
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
	__nft_build_cache(h, level, NULL, NULL, NULL);
}

void nft_release_cache(struct nft_handle *h)
{
	if (!h->cache_index)
		return;

	flush_cache(h, &h->__cache[0], NULL);
	memcpy(&h->__cache[0], &h->__cache[1], sizeof(h->__cache[0]));
	memset(&h->__cache[1], 0, sizeof(h->__cache[1]));
	h->cache_index = 0;
	h->cache = &h->__cache[0];
}

struct nftnl_table_list *nftnl_table_list_get(struct nft_handle *h)
{
	__nft_build_cache(h, NFT_CL_TABLES, NULL, NULL, NULL);

	return h->cache->tables;
}

struct nftnl_set_list *
nft_set_list_get(struct nft_handle *h, const char *table, const char *set)
{
	const struct builtin_table *t;

	t = nft_table_builtin_find(h, table);
	if (!t)
		return NULL;

	__nft_build_cache(h, NFT_CL_RULES, t, set, NULL);

	return h->cache->table[t->type].sets;
}

struct nftnl_chain_list *
nft_chain_list_get(struct nft_handle *h, const char *table, const char *chain)
{
	const struct builtin_table *t;

	t = nft_table_builtin_find(h, table);
	if (!t)
		return NULL;

	__nft_build_cache(h, NFT_CL_CHAINS, t, NULL, chain);

	return h->cache->table[t->type].chains;
}

