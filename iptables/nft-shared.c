/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2013 by Tomasz Bursztyka <tomasz.bursztyka@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <errno.h>
#include <inttypes.h>

#include <xtables.h>

#include <linux/netfilter/nf_log.h>
#include <linux/netfilter/xt_comment.h>
#include <linux/netfilter/xt_limit.h>
#include <linux/netfilter/xt_NFLOG.h>
#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/xt_pkttype.h>

#include <linux/netfilter_ipv6/ip6t_hl.h>

#include <libmnl/libmnl.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include "nft-shared.h"
#include "nft-bridge.h"
#include "xshared.h"
#include "nft.h"

extern struct nft_family_ops nft_family_ops_ipv4;
extern struct nft_family_ops nft_family_ops_ipv6;
extern struct nft_family_ops nft_family_ops_arp;
extern struct nft_family_ops nft_family_ops_bridge;

static struct nftnl_expr *xt_nftnl_expr_alloc(const char *name)
{
	struct nftnl_expr *expr = nftnl_expr_alloc(name);

	if (expr)
		return expr;

	xtables_error(RESOURCE_PROBLEM,
		      "Failed to allocate nftnl expression '%s'", name);
}

void add_meta(struct nft_handle *h, struct nftnl_rule *r, uint32_t key,
	      uint8_t *dreg)
{
	struct nftnl_expr *expr;
	uint8_t reg;

	expr = xt_nftnl_expr_alloc("meta");

	reg = NFT_REG_1;
	nftnl_expr_set_u32(expr, NFTNL_EXPR_META_KEY, key);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_META_DREG, reg);
	nftnl_rule_add_expr(r, expr);

	*dreg = reg;
}

void add_payload(struct nft_handle *h, struct nftnl_rule *r,
		 int offset, int len, uint32_t base, uint8_t *dreg)
{
	struct nftnl_expr *expr;
	uint8_t reg;

	expr = xt_nftnl_expr_alloc("payload");

	reg = NFT_REG_1;
	nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, base);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, reg);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, len);
	nftnl_rule_add_expr(r, expr);

	*dreg = reg;
}

/* bitwise operation is = sreg & mask ^ xor */
void add_bitwise_u16(struct nft_handle *h, struct nftnl_rule *r,
		     uint16_t mask, uint16_t xor, uint8_t sreg, uint8_t *dreg)
{
	struct nftnl_expr *expr;
	uint8_t reg;

	expr = xt_nftnl_expr_alloc("bitwise");

	reg = NFT_REG_1;
	nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_SREG, sreg);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_DREG, reg);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_LEN, sizeof(uint16_t));
	nftnl_expr_set(expr, NFTNL_EXPR_BITWISE_MASK, &mask, sizeof(uint16_t));
	nftnl_expr_set(expr, NFTNL_EXPR_BITWISE_XOR, &xor, sizeof(uint16_t));
	nftnl_rule_add_expr(r, expr);

	*dreg = reg;
}

void add_bitwise(struct nft_handle *h, struct nftnl_rule *r,
		 uint8_t *mask, size_t len, uint8_t sreg, uint8_t *dreg)
{
	struct nftnl_expr *expr;
	uint32_t xor[4] = { 0 };
	uint8_t reg = *dreg;

	expr = xt_nftnl_expr_alloc("bitwise");

	nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_SREG, sreg);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_DREG, reg);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_LEN, len);
	nftnl_expr_set(expr, NFTNL_EXPR_BITWISE_MASK, mask, len);
	nftnl_expr_set(expr, NFTNL_EXPR_BITWISE_XOR, &xor, len);
	nftnl_rule_add_expr(r, expr);

	*dreg = reg;
}

void add_cmp_ptr(struct nftnl_rule *r, uint32_t op, void *data, size_t len,
		 uint8_t sreg)
{
	struct nftnl_expr *expr;

	expr = xt_nftnl_expr_alloc("cmp");

	nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, sreg);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, op);
	nftnl_expr_set(expr, NFTNL_EXPR_CMP_DATA, data, len);
	nftnl_rule_add_expr(r, expr);
}

void add_cmp_u8(struct nftnl_rule *r, uint8_t val, uint32_t op, uint8_t sreg)
{
	add_cmp_ptr(r, op, &val, sizeof(val), sreg);
}

void add_cmp_u16(struct nftnl_rule *r, uint16_t val, uint32_t op, uint8_t sreg)
{
	add_cmp_ptr(r, op, &val, sizeof(val), sreg);
}

void add_cmp_u32(struct nftnl_rule *r, uint32_t val, uint32_t op, uint8_t sreg)
{
	add_cmp_ptr(r, op, &val, sizeof(val), sreg);
}

void add_iniface(struct nft_handle *h, struct nftnl_rule *r,
		 char *iface, uint32_t op)
{
	int iface_len;
	uint8_t reg;

	iface_len = strlen(iface);

	add_meta(h, r, NFT_META_IIFNAME, &reg);
	if (iface[iface_len - 1] == '+') {
		if (iface_len > 1)
			add_cmp_ptr(r, op, iface, iface_len - 1, reg);
		else if (op != NFT_CMP_EQ)
			add_cmp_ptr(r, NFT_CMP_EQ, "INVAL/D",
				    strlen("INVAL/D") + 1, reg);
	} else {
		add_cmp_ptr(r, op, iface, iface_len + 1, reg);
	}
}

void add_outiface(struct nft_handle *h, struct nftnl_rule *r,
		  char *iface, uint32_t op)
{
	int iface_len;
	uint8_t reg;

	iface_len = strlen(iface);

	add_meta(h, r, NFT_META_OIFNAME, &reg);
	if (iface[iface_len - 1] == '+') {
		if (iface_len > 1)
			add_cmp_ptr(r, op, iface, iface_len - 1, reg);
		else if (op != NFT_CMP_EQ)
			add_cmp_ptr(r, NFT_CMP_EQ, "INVAL/D",
				    strlen("INVAL/D") + 1, reg);
	} else {
		add_cmp_ptr(r, op, iface, iface_len + 1, reg);
	}
}

void add_addr(struct nft_handle *h, struct nftnl_rule *r,
	      enum nft_payload_bases base, int offset,
	      void *data, void *mask, size_t len, uint32_t op)
{
	const unsigned char *m = mask;
	bool bitwise = false;
	uint8_t reg;
	int i, j;

	for (i = 0; i < len; i++) {
		if (m[i] != 0xff) {
			bitwise = m[i] != 0;
			break;
		}
	}
	for (j = i + 1; !bitwise && j < len; j++)
		bitwise = !!m[j];

	if (!bitwise)
		len = i;

	add_payload(h, r, offset, len, base, &reg);

	if (bitwise)
		add_bitwise(h, r, mask, len, reg, &reg);

	add_cmp_ptr(r, op, data, len, reg);
}

void add_proto(struct nft_handle *h, struct nftnl_rule *r,
	       int offset, size_t len, uint8_t proto, uint32_t op)
{
	uint8_t reg;

	add_payload(h, r, offset, len, NFT_PAYLOAD_NETWORK_HEADER, &reg);
	add_cmp_u8(r, proto, op, reg);
}

void add_l4proto(struct nft_handle *h, struct nftnl_rule *r,
		 uint8_t proto, uint32_t op)
{
	uint8_t reg;

	add_meta(h, r, NFT_META_L4PROTO, &reg);
	add_cmp_u8(r, proto, op, reg);
}

bool is_same_interfaces(const char *a_iniface, const char *a_outiface,
			unsigned const char *a_iniface_mask,
			unsigned const char *a_outiface_mask,
			const char *b_iniface, const char *b_outiface,
			unsigned const char *b_iniface_mask,
			unsigned const char *b_outiface_mask)
{
	int i;

	for (i = 0; i < IFNAMSIZ; i++) {
		if (a_iniface_mask[i] != b_iniface_mask[i]) {
			DEBUGP("different iniface mask %x, %x (%d)\n",
			a_iniface_mask[i] & 0xff, b_iniface_mask[i] & 0xff, i);
			return false;
		}
		if ((a_iniface[i] & a_iniface_mask[i])
		    != (b_iniface[i] & b_iniface_mask[i])) {
			DEBUGP("different iniface\n");
			return false;
		}
		if (a_outiface_mask[i] != b_outiface_mask[i]) {
			DEBUGP("different outiface mask\n");
			return false;
		}
		if ((a_outiface[i] & a_outiface_mask[i])
		    != (b_outiface[i] & b_outiface_mask[i])) {
			DEBUGP("different outiface\n");
			return false;
		}
	}

	return true;
}

static void parse_ifname(const char *name, unsigned int len, char *dst, unsigned char *mask)
{
	if (len == 0)
		return;

	memcpy(dst, name, len);
	if (name[len - 1] == '\0') {
		if (mask)
			memset(mask, 0xff, strlen(name) + 1);
		return;
	}

	if (len >= IFNAMSIZ)
		return;

	/* wildcard */
	dst[len++] = '+';
	if (len >= IFNAMSIZ)
		return;
	dst[len++] = 0;
	if (mask)
		memset(mask, 0xff, len - 2);
}

static struct xtables_match *
nft_create_match(struct nft_xt_ctx *ctx,
		 struct iptables_command_state *cs,
		 const char *name);

static uint32_t get_meta_mask(struct nft_xt_ctx *ctx, enum nft_registers sreg)
{
	struct nft_xt_ctx_reg *reg = nft_xt_ctx_get_sreg(ctx, sreg);

	if (reg->bitwise.set)
		return reg->bitwise.mask[0];

	return ~0u;
}

static int parse_meta_mark(struct nft_xt_ctx *ctx, struct nftnl_expr *e)
{
	struct xt_mark_mtinfo1 *mark;
	struct xtables_match *match;
	uint32_t value;

	match = nft_create_match(ctx, ctx->cs, "mark");
	if (!match)
		return -1;

	mark = (void*)match->m->data;

	if (nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_OP) == NFT_CMP_NEQ)
		mark->invert = 1;

	value = nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_DATA);
	mark->mark = value;
	mark->mask = get_meta_mask(ctx, nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_SREG));

	return 0;
}

static int parse_meta_pkttype(struct nft_xt_ctx *ctx, struct nftnl_expr *e)
{
	struct xt_pkttype_info *pkttype;
	struct xtables_match *match;
	uint8_t value;

	match = nft_create_match(ctx, ctx->cs, "pkttype");
	if (!match)
		return -1;

	pkttype = (void*)match->m->data;

	if (nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_OP) == NFT_CMP_NEQ)
		pkttype->invert = 1;

	value = nftnl_expr_get_u8(e, NFTNL_EXPR_CMP_DATA);
	pkttype->pkttype = value;

	return 0;
}

int parse_meta(struct nft_xt_ctx *ctx, struct nftnl_expr *e, uint8_t key,
	       char *iniface, unsigned char *iniface_mask,
	       char *outiface, unsigned char *outiface_mask, uint8_t *invflags)
{
	uint32_t value;
	const void *ifname;
	uint32_t len;

	switch(key) {
	case NFT_META_IIF:
		value = nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_DATA);
		if (nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_IN;

		if_indextoname(value, iniface);

		memset(iniface_mask, 0xff, strlen(iniface)+1);
		break;
	case NFT_META_OIF:
		value = nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_DATA);
		if (nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_OUT;

		if_indextoname(value, outiface);

		memset(outiface_mask, 0xff, strlen(outiface)+1);
		break;
	case NFT_META_BRI_IIFNAME:
	case NFT_META_IIFNAME:
		ifname = nftnl_expr_get(e, NFTNL_EXPR_CMP_DATA, &len);
		if (nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_IN;

		parse_ifname(ifname, len, iniface, iniface_mask);
		break;
	case NFT_META_BRI_OIFNAME:
	case NFT_META_OIFNAME:
		ifname = nftnl_expr_get(e, NFTNL_EXPR_CMP_DATA, &len);
		if (nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_OUT;

		parse_ifname(ifname, len, outiface, outiface_mask);
		break;
	case NFT_META_MARK:
		parse_meta_mark(ctx, e);
		break;
	case NFT_META_PKTTYPE:
		parse_meta_pkttype(ctx, e);
		break;
	default:
		return -1;
	}

	return 0;
}

static void nft_parse_target(struct nft_xt_ctx *ctx, struct nftnl_expr *e)
{
	uint32_t tg_len;
	const char *targname = nftnl_expr_get_str(e, NFTNL_EXPR_TG_NAME);
	const void *targinfo = nftnl_expr_get(e, NFTNL_EXPR_TG_INFO, &tg_len);
	struct xtables_target *target;
	struct xt_entry_target *t;
	size_t size;

	target = xtables_find_target(targname, XTF_TRY_LOAD);
	if (target == NULL)
		return;

	size = XT_ALIGN(sizeof(struct xt_entry_target)) + tg_len;

	t = xtables_calloc(1, size);
	memcpy(&t->data, targinfo, tg_len);
	t->u.target_size = size;
	t->u.user.revision = nftnl_expr_get_u32(e, NFTNL_EXPR_TG_REV);
	strcpy(t->u.user.name, target->name);

	target->t = t;

	ctx->h->ops->parse_target(target, ctx->cs);
}

static void nft_parse_match(struct nft_xt_ctx *ctx, struct nftnl_expr *e)
{
	uint32_t mt_len;
	const char *mt_name = nftnl_expr_get_str(e, NFTNL_EXPR_MT_NAME);
	const void *mt_info = nftnl_expr_get(e, NFTNL_EXPR_MT_INFO, &mt_len);
	struct xtables_match *match;
	struct xtables_rule_match **matches;
	struct xt_entry_match *m;

	switch (ctx->h->family) {
	case NFPROTO_IPV4:
	case NFPROTO_IPV6:
	case NFPROTO_BRIDGE:
		matches = &ctx->cs->matches;
		break;
	default:
		fprintf(stderr, "BUG: nft_parse_match() unknown family %d\n",
			ctx->h->family);
		exit(EXIT_FAILURE);
	}

	match = xtables_find_match(mt_name, XTF_TRY_LOAD, matches);
	if (match == NULL)
		return;

	m = xtables_calloc(1, sizeof(struct xt_entry_match) + mt_len);
	memcpy(&m->data, mt_info, mt_len);
	m->u.match_size = mt_len + XT_ALIGN(sizeof(struct xt_entry_match));
	m->u.user.revision = nftnl_expr_get_u32(e, NFTNL_EXPR_TG_REV);
	strcpy(m->u.user.name, match->name);

	match->m = m;

	if (ctx->h->ops->parse_match != NULL)
		ctx->h->ops->parse_match(match, ctx->cs);
}

void __get_cmp_data(struct nftnl_expr *e, void *data, size_t dlen, uint8_t *op)
{
	uint32_t len;

	memcpy(data, nftnl_expr_get(e, NFTNL_EXPR_CMP_DATA, &len), dlen);
	*op = nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_OP);
}

void get_cmp_data(struct nftnl_expr *e, void *data, size_t dlen, bool *inv)
{
	uint8_t op;

	__get_cmp_data(e, data, dlen, &op);
	*inv = (op == NFT_CMP_NEQ);
}

static void nft_meta_set_to_target(struct nft_xt_ctx *ctx,
				   struct nftnl_expr *e)
{
	struct xtables_target *target;
	struct nft_xt_ctx_reg *sreg;
	enum nft_registers sregnum;
	struct xt_entry_target *t;
	unsigned int size;
	const char *targname;

	sregnum = nftnl_expr_get_u32(e, NFTNL_EXPR_META_SREG);
	sreg = nft_xt_ctx_get_sreg(ctx, sregnum);
	if (!sreg)
		return;

	switch (nftnl_expr_get_u32(e, NFTNL_EXPR_META_KEY)) {
	case NFT_META_NFTRACE:
		if ((sreg->type != NFT_XT_REG_IMMEDIATE)) {
			ctx->errmsg = "meta nftrace but reg not immediate";
			return;
		}

		if (sreg->immediate.data[0] == 0) {
			ctx->errmsg = "trace is cleared";
			return;
		}

		targname = "TRACE";
		break;
	default:
		ctx->errmsg = "meta sreg key not supported";
		return;
	}

	target = xtables_find_target(targname, XTF_TRY_LOAD);
	if (target == NULL) {
		ctx->errmsg = "target TRACE not found";
		return;
	}

	size = XT_ALIGN(sizeof(struct xt_entry_target)) + target->size;

	t = xtables_calloc(1, size);
	t->u.target_size = size;
	t->u.user.revision = target->revision;
	strcpy(t->u.user.name, targname);

	target->t = t;

	ctx->h->ops->parse_target(target, ctx->cs);
}

static void nft_parse_meta(struct nft_xt_ctx *ctx, struct nftnl_expr *e)
{
        struct nft_xt_ctx_reg *reg;

	if (nftnl_expr_is_set(e, NFTNL_EXPR_META_SREG)) {
		nft_meta_set_to_target(ctx, e);
		return;
	}

	reg = nft_xt_ctx_get_dreg(ctx, nftnl_expr_get_u32(e, NFTNL_EXPR_META_DREG));
	if (!reg)
		return;

	reg->meta_dreg.key = nftnl_expr_get_u32(e, NFTNL_EXPR_META_KEY);
	reg->type = NFT_XT_REG_META_DREG;
}

static void nft_parse_payload(struct nft_xt_ctx *ctx, struct nftnl_expr *e)
{
	enum nft_registers regnum = nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_DREG);
	struct nft_xt_ctx_reg *reg = nft_xt_ctx_get_dreg(ctx, regnum);

	if (!reg)
		return;

	reg->type = NFT_XT_REG_PAYLOAD;
	reg->payload.base = nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_BASE);
	reg->payload.offset = nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET);
	reg->payload.len = nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_LEN);
}

static void nft_parse_bitwise(struct nft_xt_ctx *ctx, struct nftnl_expr *e)
{
	enum nft_registers sregnum = nftnl_expr_get_u32(e, NFTNL_EXPR_BITWISE_SREG);
	enum nft_registers dregnum = nftnl_expr_get_u32(e, NFTNL_EXPR_BITWISE_DREG);
	struct nft_xt_ctx_reg *sreg = nft_xt_ctx_get_sreg(ctx, sregnum);
	struct nft_xt_ctx_reg *dreg = sreg;
	const void *data;
	uint32_t len;

	if (!sreg)
		return;

	if (sregnum != dregnum) {
		dreg = nft_xt_ctx_get_sreg(ctx, dregnum); /* sreg, do NOT clear ... */
		if (!dreg)
			return;

		*dreg = *sreg;  /* .. and copy content instead */
	}

	data = nftnl_expr_get(e, NFTNL_EXPR_BITWISE_XOR, &len);

	if (len > sizeof(dreg->bitwise.xor)) {
		ctx->errmsg = "bitwise xor too large";
		return;
	}

	memcpy(dreg->bitwise.xor, data, len);

	data = nftnl_expr_get(e, NFTNL_EXPR_BITWISE_MASK, &len);

	if (len > sizeof(dreg->bitwise.mask)) {
		ctx->errmsg = "bitwise mask too large";
		return;
	}

	memcpy(dreg->bitwise.mask, data, len);

	dreg->bitwise.set = true;
}

static struct xtables_match *
nft_create_match(struct nft_xt_ctx *ctx,
		 struct iptables_command_state *cs,
		 const char *name)
{
	struct xtables_match *match;
	struct xt_entry_match *m;
	unsigned int size;

	match = xtables_find_match(name, XTF_TRY_LOAD,
				   &cs->matches);
	if (!match)
		return NULL;

	size = XT_ALIGN(sizeof(struct xt_entry_match)) + match->size;
	m = xtables_calloc(1, size);
	m->u.match_size = size;
	m->u.user.revision = match->revision;

	strcpy(m->u.user.name, match->name);
	match->m = m;

	xs_init_match(match);

	return match;
}

static struct xt_udp *nft_udp_match(struct nft_xt_ctx *ctx,
			            struct iptables_command_state *cs)
{
	struct xt_udp *udp = ctx->tcpudp.udp;
	struct xtables_match *match;

	if (!udp) {
		match = nft_create_match(ctx, cs, "udp");
		if (!match)
			return NULL;

		udp = (void*)match->m->data;
		ctx->tcpudp.udp = udp;
	}

	return udp;
}

static struct xt_tcp *nft_tcp_match(struct nft_xt_ctx *ctx,
			            struct iptables_command_state *cs)
{
	struct xt_tcp *tcp = ctx->tcpudp.tcp;
	struct xtables_match *match;

	if (!tcp) {
		match = nft_create_match(ctx, cs, "tcp");
		if (!match)
			return NULL;

		tcp = (void*)match->m->data;
		ctx->tcpudp.tcp = tcp;
	}

	return tcp;
}

static void nft_parse_udp_range(struct nft_xt_ctx *ctx,
			        struct iptables_command_state *cs,
			        int sport_from, int sport_to,
			        int dport_from, int dport_to,
				uint8_t op)
{
	struct xt_udp *udp = nft_udp_match(ctx, cs);

	if (!udp)
		return;

	if (sport_from >= 0) {
		switch (op) {
		case NFT_RANGE_NEQ:
			udp->invflags |= XT_UDP_INV_SRCPT;
			/* fallthrough */
		case NFT_RANGE_EQ:
			udp->spts[0] = sport_from;
			udp->spts[1] = sport_to;
			break;
		}
	}

	if (dport_to >= 0) {
		switch (op) {
		case NFT_CMP_NEQ:
			udp->invflags |= XT_UDP_INV_DSTPT;
			/* fallthrough */
		case NFT_CMP_EQ:
			udp->dpts[0] = dport_from;
			udp->dpts[1] = dport_to;
			break;
		}
	}
}

static void nft_parse_tcp_range(struct nft_xt_ctx *ctx,
			        struct iptables_command_state *cs,
			        int sport_from, int sport_to,
			        int dport_from, int dport_to,
				uint8_t op)
{
	struct xt_tcp *tcp = nft_tcp_match(ctx, cs);

	if (!tcp)
		return;

	if (sport_from >= 0) {
		switch (op) {
		case NFT_RANGE_NEQ:
			tcp->invflags |= XT_TCP_INV_SRCPT;
			/* fallthrough */
		case NFT_RANGE_EQ:
			tcp->spts[0] = sport_from;
			tcp->spts[1] = sport_to;
			break;
		}
	}

	if (dport_to >= 0) {
		switch (op) {
		case NFT_CMP_NEQ:
			tcp->invflags |= XT_TCP_INV_DSTPT;
			/* fallthrough */
		case NFT_CMP_EQ:
			tcp->dpts[0] = dport_from;
			tcp->dpts[1] = dport_to;
			break;
		}
	}
}

static void port_match_single_to_range(__u16 *ports, __u8 *invflags,
				       uint8_t op, int port, __u8 invflag)
{
	if (port < 0)
		return;

	switch (op) {
	case NFT_CMP_NEQ:
		*invflags |= invflag;
		/* fallthrough */
	case NFT_CMP_EQ:
		ports[0] = port;
		ports[1] = port;
		break;
	case NFT_CMP_LT:
		ports[1] = max(port - 1, 1);
		break;
	case NFT_CMP_LTE:
		ports[1] = port;
		break;
	case NFT_CMP_GT:
		ports[0] = min(port + 1, UINT16_MAX);
		break;
	case NFT_CMP_GTE:
		ports[0] = port;
		break;
	}
}

static void nft_parse_udp(struct nft_xt_ctx *ctx,
			  struct iptables_command_state *cs,
			  int sport, int dport,
			  uint8_t op)
{
	struct xt_udp *udp = nft_udp_match(ctx, cs);

	if (!udp)
		return;

	port_match_single_to_range(udp->spts, &udp->invflags,
				   op, sport, XT_UDP_INV_SRCPT);
	port_match_single_to_range(udp->dpts, &udp->invflags,
				   op, dport, XT_UDP_INV_DSTPT);
}

static void nft_parse_tcp(struct nft_xt_ctx *ctx,
			  struct iptables_command_state *cs,
			  int sport, int dport,
			  uint8_t op)
{
	struct xt_tcp *tcp = nft_tcp_match(ctx, cs);

	if (!tcp)
		return;

	port_match_single_to_range(tcp->spts, &tcp->invflags,
				   op, sport, XT_TCP_INV_SRCPT);
	port_match_single_to_range(tcp->dpts, &tcp->invflags,
				   op, dport, XT_TCP_INV_DSTPT);
}

static void nft_parse_th_port(struct nft_xt_ctx *ctx,
			      struct iptables_command_state *cs,
			      uint8_t proto,
			      int sport, int dport, uint8_t op)
{
	switch (proto) {
	case IPPROTO_UDP:
		nft_parse_udp(ctx, cs, sport, dport, op);
		break;
	case IPPROTO_TCP:
		nft_parse_tcp(ctx, cs, sport, dport, op);
		break;
	}
}

static void nft_parse_th_port_range(struct nft_xt_ctx *ctx,
				    struct iptables_command_state *cs,
				    uint8_t proto,
				    int sport_from, int sport_to,
				    int dport_from, int dport_to, uint8_t op)
{
	switch (proto) {
	case IPPROTO_UDP:
		nft_parse_udp_range(ctx, cs, sport_from, sport_to, dport_from, dport_to, op);
		break;
	case IPPROTO_TCP:
		nft_parse_tcp_range(ctx, cs, sport_from, sport_to, dport_from, dport_to, op);
		break;
	}
}

static void nft_parse_tcp_flags(struct nft_xt_ctx *ctx,
				struct iptables_command_state *cs,
				uint8_t op, uint8_t flags, uint8_t mask)
{
	struct xt_tcp *tcp = nft_tcp_match(ctx, cs);

	if (!tcp)
		return;

	if (op == NFT_CMP_NEQ)
		tcp->invflags |= XT_TCP_INV_FLAGS;
	tcp->flg_cmp = flags;
	tcp->flg_mask = mask;
}

static void nft_parse_transport(struct nft_xt_ctx *ctx,
				struct nftnl_expr *e,
				struct iptables_command_state *cs)
{
	struct nft_xt_ctx_reg *sreg;
	enum nft_registers reg;
	uint32_t sdport;
	uint16_t port;
	uint8_t proto, op;
	unsigned int len;

	switch (ctx->h->family) {
	case NFPROTO_IPV4:
		proto = ctx->cs->fw.ip.proto;
		break;
	case NFPROTO_IPV6:
		proto = ctx->cs->fw6.ipv6.proto;
		break;
	default:
		proto = 0;
		break;
	}

	nftnl_expr_get(e, NFTNL_EXPR_CMP_DATA, &len);
	op = nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_OP);

	reg = nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_SREG);
	sreg = nft_xt_ctx_get_sreg(ctx, reg);
	if (!sreg)
		return;

	if (sreg->type != NFT_XT_REG_PAYLOAD) {
		ctx->errmsg = "sgreg not payload";
		return;
	}

	switch(sreg->payload.offset) {
	case 0: /* th->sport */
		switch (len) {
		case 2: /* load sport only */
			port = ntohs(nftnl_expr_get_u16(e, NFTNL_EXPR_CMP_DATA));
			nft_parse_th_port(ctx, cs, proto, port, -1, op);
			return;
		case 4: /* load both src and dst port */
			sdport = ntohl(nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_DATA));
			nft_parse_th_port(ctx, cs, proto, sdport >> 16, sdport & 0xffff, op);
			return;
		}
		break;
	case 2: /* th->dport */
		switch (len) {
		case 2:
			port = ntohs(nftnl_expr_get_u16(e, NFTNL_EXPR_CMP_DATA));
			nft_parse_th_port(ctx, cs, proto, -1, port, op);
			return;
		}
		break;
	case 13: /* th->flags */
		if (len == 1 && proto == IPPROTO_TCP) {
			uint8_t flags = nftnl_expr_get_u8(e, NFTNL_EXPR_CMP_DATA);
			uint8_t mask = ~0;

			if (sreg->bitwise.set)
				memcpy(&mask, &sreg->bitwise.mask, sizeof(mask));

			nft_parse_tcp_flags(ctx, cs, op, flags, mask);
		}
		return;
	}
}

static void nft_parse_transport_range(struct nft_xt_ctx *ctx,
				      const struct nft_xt_ctx_reg *sreg,
				      struct nftnl_expr *e,
				      struct iptables_command_state *cs)
{
	unsigned int len_from, len_to;
	uint8_t proto, op;
	uint16_t from, to;

	switch (ctx->h->family) {
	case NFPROTO_IPV4:
		proto = ctx->cs->fw.ip.proto;
		break;
	case NFPROTO_IPV6:
		proto = ctx->cs->fw6.ipv6.proto;
		break;
	default:
		proto = 0;
		break;
	}

	nftnl_expr_get(e, NFTNL_EXPR_RANGE_FROM_DATA, &len_from);
	nftnl_expr_get(e, NFTNL_EXPR_RANGE_FROM_DATA, &len_to);
	if (len_to != len_from || len_to != 2)
		return;

	op = nftnl_expr_get_u32(e, NFTNL_EXPR_RANGE_OP);

	from = ntohs(nftnl_expr_get_u16(e, NFTNL_EXPR_RANGE_FROM_DATA));
	to = ntohs(nftnl_expr_get_u16(e, NFTNL_EXPR_RANGE_TO_DATA));

	switch (sreg->payload.offset) {
	case 0:
		nft_parse_th_port_range(ctx, cs, proto, from, to, -1, -1, op);
		return;
	case 2:
		to = ntohs(nftnl_expr_get_u16(e, NFTNL_EXPR_RANGE_TO_DATA));
		nft_parse_th_port_range(ctx, cs, proto, -1, -1, from, to, op);
		return;
	}
}

static void nft_parse_cmp(struct nft_xt_ctx *ctx, struct nftnl_expr *e)
{
	struct nft_xt_ctx_reg *sreg;
	uint32_t reg;

	reg = nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_SREG);

	sreg = nft_xt_ctx_get_sreg(ctx, reg);
	if (!sreg)
		return;

	switch (sreg->type) {
	case NFT_XT_REG_UNDEF:
		ctx->errmsg = "cmp sreg undef";
		break;
	case NFT_XT_REG_META_DREG:
		ctx->h->ops->parse_meta(ctx, sreg, e, ctx->cs);
		break;
	case NFT_XT_REG_PAYLOAD:
		switch (sreg->payload.base) {
		case NFT_PAYLOAD_LL_HEADER:
			if (ctx->h->family == NFPROTO_BRIDGE)
				ctx->h->ops->parse_payload(ctx, sreg, e, ctx->cs);
			break;
		case NFT_PAYLOAD_NETWORK_HEADER:
			ctx->h->ops->parse_payload(ctx, sreg, e, ctx->cs);
			break;
		case NFT_PAYLOAD_TRANSPORT_HEADER:
			nft_parse_transport(ctx, e, ctx->cs);
			break;
		}

		break;
	default:
		ctx->errmsg = "cmp sreg has unknown type";
		break;
	}
}

static void nft_parse_counter(struct nftnl_expr *e, struct xt_counters *counters)
{
	counters->pcnt = nftnl_expr_get_u64(e, NFTNL_EXPR_CTR_PACKETS);
	counters->bcnt = nftnl_expr_get_u64(e, NFTNL_EXPR_CTR_BYTES);
}

static void nft_parse_immediate(struct nft_xt_ctx *ctx, struct nftnl_expr *e)
{
	const char *chain = nftnl_expr_get_str(e, NFTNL_EXPR_IMM_CHAIN);
	struct iptables_command_state *cs = ctx->cs;
	struct xt_entry_target *t;
	uint32_t size;
	int verdict;

	if (nftnl_expr_is_set(e, NFTNL_EXPR_IMM_DATA)) {
		struct nft_xt_ctx_reg *dreg;
		const void *imm_data;
		uint32_t len;

		imm_data = nftnl_expr_get(e, NFTNL_EXPR_IMM_DATA, &len);
		dreg = nft_xt_ctx_get_dreg(ctx, nftnl_expr_get_u32(e, NFTNL_EXPR_IMM_DREG));
		if (!dreg)
			return;

		if (len > sizeof(dreg->immediate.data))
			return;

		memcpy(dreg->immediate.data, imm_data, len);
		dreg->immediate.len = len;
		dreg->type = NFT_XT_REG_IMMEDIATE;

		return;
	}

	verdict = nftnl_expr_get_u32(e, NFTNL_EXPR_IMM_VERDICT);
	/* Standard target? */
	switch(verdict) {
	case NF_ACCEPT:
		cs->jumpto = "ACCEPT";
		break;
	case NF_DROP:
		cs->jumpto = "DROP";
		break;
	case NFT_RETURN:
		cs->jumpto = "RETURN";
		break;;
	case NFT_GOTO:
		if (ctx->h->ops->set_goto_flag)
			ctx->h->ops->set_goto_flag(cs);
		/* fall through */
	case NFT_JUMP:
		cs->jumpto = chain;
		/* fall through */
	default:
		return;
	}

	cs->target = xtables_find_target(cs->jumpto, XTF_TRY_LOAD);
	if (!cs->target)
		return;

	size = XT_ALIGN(sizeof(struct xt_entry_target)) + cs->target->size;
	t = xtables_calloc(1, size);
	t->u.target_size = size;
	t->u.user.revision = cs->target->revision;
	strcpy(t->u.user.name, cs->jumpto);
	cs->target->t = t;
}

static void nft_parse_limit(struct nft_xt_ctx *ctx, struct nftnl_expr *e)
{
	__u32 burst = nftnl_expr_get_u32(e, NFTNL_EXPR_LIMIT_BURST);
	__u64 unit = nftnl_expr_get_u64(e, NFTNL_EXPR_LIMIT_UNIT);
	__u64 rate = nftnl_expr_get_u64(e, NFTNL_EXPR_LIMIT_RATE);
	struct xtables_rule_match **matches;
	struct xtables_match *match;
	struct xt_rateinfo *rinfo;
	size_t size;

	switch (ctx->h->family) {
	case NFPROTO_IPV4:
	case NFPROTO_IPV6:
	case NFPROTO_BRIDGE:
		matches = &ctx->cs->matches;
		break;
	default:
		fprintf(stderr, "BUG: nft_parse_limit() unknown family %d\n",
			ctx->h->family);
		exit(EXIT_FAILURE);
	}

	match = xtables_find_match("limit", XTF_TRY_LOAD, matches);
	if (match == NULL)
		return;

	size = XT_ALIGN(sizeof(struct xt_entry_match)) + match->size;
	match->m = xtables_calloc(1, size);
	match->m->u.match_size = size;
	strcpy(match->m->u.user.name, match->name);
	match->m->u.user.revision = match->revision;
	xs_init_match(match);

	rinfo = (void *)match->m->data;
	rinfo->avg = XT_LIMIT_SCALE * unit / rate;
	rinfo->burst = burst;

	if (ctx->h->ops->parse_match != NULL)
		ctx->h->ops->parse_match(match, ctx->cs);
}

static void nft_parse_log(struct nft_xt_ctx *ctx, struct nftnl_expr *e)
{
	struct xtables_target *target;
	struct xt_entry_target *t;
	size_t target_size;
	/*
	 * In order to handle the longer log-prefix supported by nft, instead of
	 * using struct xt_nflog_info, we use a struct with a compatible layout, but
	 * a larger buffer for the prefix.
	 */
	struct xt_nflog_info_nft {
		__u32 len;
		__u16 group;
		__u16 threshold;
		__u16 flags;
		__u16 pad;
		char  prefix[NF_LOG_PREFIXLEN];
	} info = {
		.group     = nftnl_expr_get_u16(e, NFTNL_EXPR_LOG_GROUP),
		.threshold = nftnl_expr_get_u16(e, NFTNL_EXPR_LOG_QTHRESHOLD),
	};
	if (nftnl_expr_is_set(e, NFTNL_EXPR_LOG_SNAPLEN)) {
		info.len = nftnl_expr_get_u32(e, NFTNL_EXPR_LOG_SNAPLEN);
		info.flags = XT_NFLOG_F_COPY_LEN;
	}
	if (nftnl_expr_is_set(e, NFTNL_EXPR_LOG_PREFIX))
		snprintf(info.prefix, sizeof(info.prefix), "%s",
			 nftnl_expr_get_str(e, NFTNL_EXPR_LOG_PREFIX));

	target = xtables_find_target("NFLOG", XTF_TRY_LOAD);
	if (target == NULL)
		return;

	target_size = XT_ALIGN(sizeof(struct xt_entry_target)) +
		      XT_ALIGN(sizeof(struct xt_nflog_info_nft));

	t = xtables_calloc(1, target_size);
	t->u.target_size = target_size;
	strcpy(t->u.user.name, target->name);
	t->u.user.revision = target->revision;

	target->t = t;

	memcpy(&target->t->data, &info, sizeof(info));

	ctx->h->ops->parse_target(target, ctx->cs);
}

static void nft_parse_lookup(struct nft_xt_ctx *ctx, struct nft_handle *h,
			     struct nftnl_expr *e)
{
	if (ctx->h->ops->parse_lookup)
		ctx->h->ops->parse_lookup(ctx, e);
}

static void nft_parse_range(struct nft_xt_ctx *ctx, struct nftnl_expr *e)
{
	struct nft_xt_ctx_reg *sreg;
	uint32_t reg;

	reg = nftnl_expr_get_u32(e, NFTNL_EXPR_RANGE_SREG);
	sreg = nft_xt_ctx_get_sreg(ctx, reg);

	switch (sreg->type) {
	case NFT_XT_REG_UNDEF:
		ctx->errmsg = "range sreg undef";
		break;
	case NFT_XT_REG_PAYLOAD:
		switch (sreg->payload.base) {
		case NFT_PAYLOAD_TRANSPORT_HEADER:
			nft_parse_transport_range(ctx, sreg, e, ctx->cs);
			break;
		default:
			ctx->errmsg = "range with unknown payload base";
			break;
		}
		break;
	default:
		ctx->errmsg = "range sreg type unsupported";
		break;
	}
}

bool nft_rule_to_iptables_command_state(struct nft_handle *h,
					const struct nftnl_rule *r,
					struct iptables_command_state *cs)
{
	struct nftnl_expr_iter *iter;
	struct nftnl_expr *expr;
	struct nft_xt_ctx ctx = {
		.cs = cs,
		.h = h,
		.table = nftnl_rule_get_str(r, NFTNL_RULE_TABLE),
	};
	bool ret = true;

	iter = nftnl_expr_iter_create(r);
	if (iter == NULL)
		return false;

	ctx.iter = iter;
	expr = nftnl_expr_iter_next(iter);
	while (expr != NULL) {
		const char *name =
			nftnl_expr_get_str(expr, NFTNL_EXPR_NAME);

		if (strcmp(name, "counter") == 0)
			nft_parse_counter(expr, &ctx.cs->counters);
		else if (strcmp(name, "payload") == 0)
			nft_parse_payload(&ctx, expr);
		else if (strcmp(name, "meta") == 0)
			nft_parse_meta(&ctx, expr);
		else if (strcmp(name, "bitwise") == 0)
			nft_parse_bitwise(&ctx, expr);
		else if (strcmp(name, "cmp") == 0)
			nft_parse_cmp(&ctx, expr);
		else if (strcmp(name, "immediate") == 0)
			nft_parse_immediate(&ctx, expr);
		else if (strcmp(name, "match") == 0)
			nft_parse_match(&ctx, expr);
		else if (strcmp(name, "target") == 0)
			nft_parse_target(&ctx, expr);
		else if (strcmp(name, "limit") == 0)
			nft_parse_limit(&ctx, expr);
		else if (strcmp(name, "lookup") == 0)
			nft_parse_lookup(&ctx, h, expr);
		else if (strcmp(name, "log") == 0)
			nft_parse_log(&ctx, expr);
		else if (strcmp(name, "range") == 0)
			nft_parse_range(&ctx, expr);

		if (ctx.errmsg) {
			fprintf(stderr, "%s", ctx.errmsg);
			ctx.errmsg = NULL;
			ret = false;
		}

		expr = nftnl_expr_iter_next(iter);
	}

	nftnl_expr_iter_destroy(iter);

	if (nftnl_rule_is_set(r, NFTNL_RULE_USERDATA)) {
		const void *data;
		uint32_t len, size;
		const char *comment;

		data = nftnl_rule_get_data(r, NFTNL_RULE_USERDATA, &len);
		comment = get_comment(data, len);
		if (comment) {
			struct xtables_match *match;
			struct xt_entry_match *m;

			match = xtables_find_match("comment", XTF_TRY_LOAD,
						   &cs->matches);
			if (match == NULL)
				return false;

			size = XT_ALIGN(sizeof(struct xt_entry_match))
				+ match->size;
			m = xtables_calloc(1, size);

			strncpy((char *)m->data, comment, match->size - 1);
			m->u.match_size = size;
			m->u.user.revision = 0;
			strcpy(m->u.user.name, match->name);

			match->m = m;
		}
	}

	if (!cs->jumpto)
		cs->jumpto = "";

	return ret;
}

void nft_ipv46_save_chain(const struct nftnl_chain *c, const char *policy)
{
	const char *chain = nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);
	uint64_t pkts = nftnl_chain_get_u64(c, NFTNL_CHAIN_PACKETS);
	uint64_t bytes = nftnl_chain_get_u64(c, NFTNL_CHAIN_BYTES);

	printf(":%s %s [%"PRIu64":%"PRIu64"]\n",
	       chain, policy ?: "-", pkts, bytes);
}

void save_matches_and_target(const struct iptables_command_state *cs,
			     bool goto_flag, const void *fw,
			     unsigned int format)
{
	struct xtables_rule_match *matchp;

	for (matchp = cs->matches; matchp; matchp = matchp->next) {
		if (matchp->match->alias) {
			printf(" -m %s",
			       matchp->match->alias(matchp->match->m));
		} else
			printf(" -m %s", matchp->match->name);

		if (matchp->match->save != NULL) {
			/* cs->fw union makes the trick */
			matchp->match->save(fw, matchp->match->m);
		}
	}

	if ((format & (FMT_NOCOUNTS | FMT_C_COUNTS)) == FMT_C_COUNTS)
		printf(" -c %llu %llu",
		       (unsigned long long)cs->counters.pcnt,
		       (unsigned long long)cs->counters.bcnt);

	if (cs->target != NULL) {
		if (cs->target->alias) {
			printf(" -j %s", cs->target->alias(cs->target->t));
		} else
			printf(" -j %s", cs->jumpto);

		if (cs->target->save != NULL) {
			cs->target->save(fw, cs->target->t);
		}
	} else if (strlen(cs->jumpto) > 0) {
		printf(" -%c %s", goto_flag ? 'g' : 'j', cs->jumpto);
	}

	printf("\n");
}

void print_matches_and_target(struct iptables_command_state *cs,
			      unsigned int format)
{
	struct xtables_rule_match *matchp;

	for (matchp = cs->matches; matchp; matchp = matchp->next) {
		if (matchp->match->print != NULL) {
			matchp->match->print(&cs->fw, matchp->match->m,
					     format & FMT_NUMERIC);
		}
	}

	if (cs->target != NULL) {
		if (cs->target->print != NULL) {
			cs->target->print(&cs->fw, cs->target->t,
					  format & FMT_NUMERIC);
		}
	}
}

struct nft_family_ops *nft_family_ops_lookup(int family)
{
	switch (family) {
	case AF_INET:
		return &nft_family_ops_ipv4;
	case AF_INET6:
		return &nft_family_ops_ipv6;
	case NFPROTO_ARP:
		return &nft_family_ops_arp;
	case NFPROTO_BRIDGE:
		return &nft_family_ops_bridge;
	default:
		break;
	}

	return NULL;
}

bool compare_matches(struct xtables_rule_match *mt1,
		     struct xtables_rule_match *mt2)
{
	struct xtables_rule_match *mp1;
	struct xtables_rule_match *mp2;

	for (mp1 = mt1, mp2 = mt2; mp1 && mp2; mp1 = mp1->next, mp2 = mp2->next) {
		struct xt_entry_match *m1 = mp1->match->m;
		struct xt_entry_match *m2 = mp2->match->m;

		if (strcmp(m1->u.user.name, m2->u.user.name) != 0) {
			DEBUGP("mismatching match name\n");
			return false;
		}

		if (m1->u.user.match_size != m2->u.user.match_size) {
			DEBUGP("mismatching match size\n");
			return false;
		}

		if (memcmp(m1->data, m2->data,
			   mp1->match->userspacesize) != 0) {
			DEBUGP("mismatch match data\n");
			return false;
		}
	}

	/* Both cursors should be NULL */
	if (mp1 != mp2) {
		DEBUGP("mismatch matches amount\n");
		return false;
	}

	return true;
}

bool compare_targets(struct xtables_target *tg1, struct xtables_target *tg2)
{
	if (tg1 == NULL && tg2 == NULL)
		return true;

	if (tg1 == NULL || tg2 == NULL)
		return false;
	if (tg1->userspacesize != tg2->userspacesize)
		return false;

	if (strcmp(tg1->t->u.user.name, tg2->t->u.user.name) != 0)
		return false;

	if (memcmp(tg1->t->data, tg2->t->data, tg1->userspacesize) != 0)
		return false;

	return true;
}

void nft_ipv46_parse_target(struct xtables_target *t,
			    struct iptables_command_state *cs)
{
	cs->target = t;
	cs->jumpto = t->name;
}

void nft_check_xt_legacy(int family, bool is_ipt_save)
{
	static const char tables6[] = "/proc/net/ip6_tables_names";
	static const char tables4[] = "/proc/net/ip_tables_names";
	static const char tablesa[] = "/proc/net/arp_tables_names";
	const char *prefix = "ip";
	FILE *fp = NULL;
	char buf[1024];

	switch (family) {
	case NFPROTO_IPV4:
		fp = fopen(tables4, "r");
		break;
	case NFPROTO_IPV6:
		fp = fopen(tables6, "r");
		prefix = "ip6";
		break;
	case NFPROTO_ARP:
		fp = fopen(tablesa, "r");
		prefix = "arp";
		break;
	default:
		break;
	}

	if (!fp)
		return;

	if (fgets(buf, sizeof(buf), fp))
		fprintf(stderr, "# Warning: %stables-legacy tables present, use %stables-legacy%s to see them\n",
			prefix, prefix, is_ipt_save ? "-save" : "");
	fclose(fp);
}

int nft_parse_hl(struct nft_xt_ctx *ctx,
		 struct nftnl_expr *e,
		 struct iptables_command_state *cs)
{
	struct xtables_match *match;
	struct ip6t_hl_info *info;
	uint8_t hl, mode;
	int op;

	hl = nftnl_expr_get_u8(e, NFTNL_EXPR_CMP_DATA);
	op = nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_OP);

	switch (op) {
	case NFT_CMP_NEQ:
		mode = IP6T_HL_NE;
		break;
	case NFT_CMP_EQ:
		mode = IP6T_HL_EQ;
		break;
	case NFT_CMP_LT:
		mode = IP6T_HL_LT;
		break;
	case NFT_CMP_GT:
		mode = IP6T_HL_GT;
		break;
	case NFT_CMP_LTE:
		mode = IP6T_HL_LT;
		if (hl == 255)
			return -1;
		hl++;
		break;
	case NFT_CMP_GTE:
		mode = IP6T_HL_GT;
		if (hl == 0)
			return -1;
		hl--;
		break;
	default:
		return -1;
	}

	/* ipt_ttl_info and ip6t_hl_info have same layout,
	 * IPT_TTL_x and IP6T_HL_x are aliases as well, so
	 * just use HL for both ipv4 and ipv6.
	 */
	switch (ctx->h->family) {
	case NFPROTO_IPV4:
		match = nft_create_match(ctx, ctx->cs, "ttl");
		break;
	case NFPROTO_IPV6:
		match = nft_create_match(ctx, ctx->cs, "hl");
		break;
	default:
		return -1;
	}

	if (!match)
		return -1;

	info = (void*)match->m->data;
	info->hop_limit = hl;
	info->mode = mode;

	return 0;
}

enum nft_registers nft_get_next_reg(enum nft_registers reg, size_t size)
{
	/* convert size to NETLINK_ALIGN-sized chunks */
	size = (size + NETLINK_ALIGN - 1) / NETLINK_ALIGN;

	/* map 16byte reg to 4byte one */
	if (reg < __NFT_REG_MAX)
		reg = NFT_REG32_00 + (reg - 1) * NFT_REG_SIZE / NFT_REG32_SIZE;

	reg += size;
	assert(reg <= NFT_REG32_15);

	return reg;
}
