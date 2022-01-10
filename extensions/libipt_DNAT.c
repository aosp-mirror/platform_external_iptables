#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <xtables.h>
#include <iptables.h> /* get_kernel_version */
#include <limits.h> /* INT_MAX in ip_tables.h */
#include <arpa/inet.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/nf_nat.h>

enum {
	O_TO_DEST = 0,
	O_RANDOM,
	O_PERSISTENT,
	F_TO_DEST = 1 << O_TO_DEST,
	F_RANDOM  = 1 << O_RANDOM,
};

static void DNAT_help(void)
{
	printf(
"DNAT target options:\n"
" --to-destination [<ipaddr>[-<ipaddr>]][:port[-port]]\n"
"				Address to map destination to.\n"
"[--random] [--persistent]\n");
}

static void DNAT_help_v2(void)
{
	printf(
"DNAT target options:\n"
" --to-destination [<ipaddr>[-<ipaddr>]][:port[-port[/port]]]\n"
"				Address to map destination to.\n"
"[--random] [--persistent]\n");
}

static const struct xt_option_entry DNAT_opts[] = {
	{.name = "to-destination", .id = O_TO_DEST, .type = XTTYPE_STRING,
	 .flags = XTOPT_MAND},
	{.name = "random", .id = O_RANDOM, .type = XTTYPE_NONE},
	{.name = "persistent", .id = O_PERSISTENT, .type = XTTYPE_NONE},
	XTOPT_TABLEEND,
};

/* Parses ports */
static void
parse_ports(const char *arg, bool portok, struct nf_nat_range2 *range)
{
	unsigned int port, maxport, baseport;
	char *end = NULL;

	if (!portok)
		xtables_error(PARAMETER_PROBLEM,
			      "Need TCP, UDP, SCTP or DCCP with port specification");

	range->flags |= NF_NAT_RANGE_PROTO_SPECIFIED;

	if (!xtables_strtoui(arg, &end, &port, 1, UINT16_MAX))
		xtables_error(PARAMETER_PROBLEM,
			      "Port `%s' not valid", arg);

	switch (*end) {
	case '\0':
		range->min_proto.tcp.port
			= range->max_proto.tcp.port
			= htons(port);
		return;
	case '-':
		arg = end + 1;
		break;
	case ':':
		xtables_error(PARAMETER_PROBLEM,
			      "Invalid port:port syntax - use dash");
	default:
		xtables_error(PARAMETER_PROBLEM,
			      "Garbage after port value: `%s'", end);
	}

	if (!xtables_strtoui(arg, &end, &maxport, 1, UINT16_MAX))
		xtables_error(PARAMETER_PROBLEM,
			      "Port `%s' not valid", arg);

	if (maxport < port)
		/* People are stupid. */
		xtables_error(PARAMETER_PROBLEM,
			   "Port range `%s' funky", arg);

	range->min_proto.tcp.port = htons(port);
	range->max_proto.tcp.port = htons(maxport);

	switch (*end) {
	case '\0':
		return;
	case '/':
		arg = end + 1;
		break;
	default:
		xtables_error(PARAMETER_PROBLEM,
			      "Garbage after port range: `%s'", end);
	}

	if (!xtables_strtoui(arg, &end, &baseport, 1, UINT16_MAX))
		xtables_error(PARAMETER_PROBLEM,
			      "Port `%s' not valid", arg);

	range->flags |= NF_NAT_RANGE_PROTO_OFFSET;
	range->base_proto.tcp.port = htons(baseport);
}

/* Ranges expected in network order. */
static void
parse_to(const char *orig_arg, bool portok, struct nf_nat_range2 *range)
{
	char *arg, *colon, *dash;

	arg = xtables_strdup(orig_arg);
	colon = strchr(arg, ':');

	if (colon) {
		parse_ports(colon + 1, portok, range);

		/* Starts with a colon? No IP info...*/
		if (colon == arg) {
			free(arg);
			return;
		}
		*colon = '\0';
	}

	range->flags |= NF_NAT_RANGE_MAP_IPS;
	dash = strchr(arg, '-');
	if (colon && dash && dash > colon)
		dash = NULL;

	if (dash)
		*dash = '\0';

	if (!inet_pton(AF_INET, arg, &range->min_addr))
		xtables_error(PARAMETER_PROBLEM,
			      "Bad IP address \"%s\"\n", arg);
	if (dash) {
		if (!inet_pton(AF_INET, dash + 1, &range->max_addr))
			xtables_error(PARAMETER_PROBLEM,
				      "Bad IP address \"%s\"\n", dash + 1);
	} else {
		range->max_addr = range->min_addr;
	}
	free(arg);
	return;
}

static void __DNAT_parse(struct xt_option_call *cb, __u16 proto,
			 struct nf_nat_range2 *range)
{
	bool portok = proto == IPPROTO_TCP ||
		      proto == IPPROTO_UDP ||
		      proto == IPPROTO_SCTP ||
		      proto == IPPROTO_DCCP ||
		      proto == IPPROTO_ICMP;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TO_DEST:
		parse_to(cb->arg, portok, range);
		break;
	case O_PERSISTENT:
		range->flags |= NF_NAT_RANGE_PERSISTENT;
		break;
	}
}

static void DNAT_parse(struct xt_option_call *cb)
{
	struct nf_nat_ipv4_multi_range_compat *mr = (void *)cb->data;
	const struct ipt_entry *entry = cb->xt_entry;
	struct nf_nat_range2 range = {};

	__DNAT_parse(cb, entry->ip.proto, &range);

	switch (cb->entry->id) {
	case O_TO_DEST:
		mr->range->min_ip = range.min_addr.ip;
		mr->range->max_ip = range.max_addr.ip;
		mr->range->min = range.min_proto;
		mr->range->max = range.max_proto;
		/* fall through */
	case O_PERSISTENT:
		mr->range->flags |= range.flags;
		break;
	}
}

static void DNAT_fcheck(struct xt_fcheck_call *cb)
{
	static const unsigned int f = F_TO_DEST | F_RANDOM;
	struct nf_nat_ipv4_multi_range_compat *mr = cb->data;

	if ((cb->xflags & f) == f)
		mr->range[0].flags |= NF_NAT_RANGE_PROTO_RANDOM;

	mr->rangesize = 1;

	if (mr->range[0].flags & NF_NAT_RANGE_PROTO_OFFSET)
		xtables_error(PARAMETER_PROBLEM,
			      "Shifted portmap ranges not supported with this kernel");
}

static void print_range(const struct nf_nat_ipv4_range *r)
{
	if (r->flags & NF_NAT_RANGE_MAP_IPS) {
		struct in_addr a;

		a.s_addr = r->min_ip;
		printf("%s", xtables_ipaddr_to_numeric(&a));
		if (r->max_ip != r->min_ip) {
			a.s_addr = r->max_ip;
			printf("-%s", xtables_ipaddr_to_numeric(&a));
		}
	}
	if (r->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		printf(":");
		printf("%hu", ntohs(r->min.tcp.port));
		if (r->max.tcp.port != r->min.tcp.port)
			printf("-%hu", ntohs(r->max.tcp.port));
	}
}

static void DNAT_print(const void *ip, const struct xt_entry_target *target,
                       int numeric)
{
	const struct nf_nat_ipv4_multi_range_compat *mr =
				(const void *)target->data;

	printf(" to:");
	print_range(mr->range);
	if (mr->range->flags & NF_NAT_RANGE_PROTO_RANDOM)
		printf(" random");
	if (mr->range->flags & NF_NAT_RANGE_PERSISTENT)
		printf(" persistent");
}

static void DNAT_save(const void *ip, const struct xt_entry_target *target)
{
	const struct nf_nat_ipv4_multi_range_compat *mr =
				(const void *)target->data;

	printf(" --to-destination ");
	print_range(mr->range);
	if (mr->range->flags & NF_NAT_RANGE_PROTO_RANDOM)
		printf(" --random");
	if (mr->range->flags & NF_NAT_RANGE_PERSISTENT)
		printf(" --persistent");
}

static void print_range_xlate(const struct nf_nat_ipv4_range *r,
			struct xt_xlate *xl)
{
	if (r->flags & NF_NAT_RANGE_MAP_IPS) {
		struct in_addr a;

		a.s_addr = r->min_ip;
		xt_xlate_add(xl, "%s", xtables_ipaddr_to_numeric(&a));
		if (r->max_ip != r->min_ip) {
			a.s_addr = r->max_ip;
			xt_xlate_add(xl, "-%s", xtables_ipaddr_to_numeric(&a));
		}
	}
	if (r->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		xt_xlate_add(xl, ":%hu", ntohs(r->min.tcp.port));
		if (r->max.tcp.port != r->min.tcp.port)
			xt_xlate_add(xl, "-%hu", ntohs(r->max.tcp.port));
	}
}

static int DNAT_xlate(struct xt_xlate *xl,
		      const struct xt_xlate_tg_params *params)
{
	const struct nf_nat_ipv4_multi_range_compat *mr =
			(const void *)params->target->data;
	bool sep_need = false;
	const char *sep = " ";

	xt_xlate_add(xl, "dnat to ");
	print_range_xlate(mr->range, xl);
	if (mr->range->flags & NF_NAT_RANGE_PROTO_RANDOM) {
		xt_xlate_add(xl, " random");
		sep_need = true;
	}
	if (mr->range->flags & NF_NAT_RANGE_PERSISTENT) {
		if (sep_need)
			sep = ",";
		xt_xlate_add(xl, "%spersistent", sep);
	}

	return 1;
}

static void DNAT_parse_v2(struct xt_option_call *cb)
{
	const struct ipt_entry *entry = cb->xt_entry;

	__DNAT_parse(cb, entry->ip.proto, cb->data);
}

static void DNAT_fcheck_v2(struct xt_fcheck_call *cb)
{
	static const unsigned int f = F_TO_DEST | F_RANDOM;
	struct nf_nat_range2 *range = cb->data;

	if ((cb->xflags & f) == f)
		range->flags |= NF_NAT_RANGE_PROTO_RANDOM;
}

static void print_range_v2(const struct nf_nat_range2 *range)
{
	if (range->flags & NF_NAT_RANGE_MAP_IPS) {
		printf("%s", xtables_ipaddr_to_numeric(&range->min_addr.in));
		if (memcmp(&range->min_addr, &range->max_addr,
			   sizeof(range->min_addr)))
			printf("-%s", xtables_ipaddr_to_numeric(&range->max_addr.in));
	}
	if (range->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		printf(":");
		printf("%hu", ntohs(range->min_proto.tcp.port));
		if (range->max_proto.tcp.port != range->min_proto.tcp.port)
			printf("-%hu", ntohs(range->max_proto.tcp.port));
		if (range->flags & NF_NAT_RANGE_PROTO_OFFSET)
			printf("/%hu", ntohs(range->base_proto.tcp.port));
	}
}

static void DNAT_print_v2(const void *ip, const struct xt_entry_target *target,
                       int numeric)
{
	const struct nf_nat_range2 *range = (const void *)target->data;

	printf(" to:");
	print_range_v2(range);
	if (range->flags & NF_NAT_RANGE_PROTO_RANDOM)
		printf(" random");
	if (range->flags & NF_NAT_RANGE_PERSISTENT)
		printf(" persistent");
}

static void DNAT_save_v2(const void *ip, const struct xt_entry_target *target)
{
	const struct nf_nat_range2 *range = (const void *)target->data;

	printf(" --to-destination ");
	print_range_v2(range);
	if (range->flags & NF_NAT_RANGE_PROTO_RANDOM)
		printf(" --random");
	if (range->flags & NF_NAT_RANGE_PERSISTENT)
		printf(" --persistent");
}

static void print_range_xlate_v2(const struct nf_nat_range2 *range,
			      struct xt_xlate *xl)
{
	if (range->flags & NF_NAT_RANGE_MAP_IPS) {
		xt_xlate_add(xl, "%s", xtables_ipaddr_to_numeric(&range->min_addr.in));
		if (memcmp(&range->min_addr, &range->max_addr,
			   sizeof(range->min_addr))) {
			xt_xlate_add(xl, "-%s", xtables_ipaddr_to_numeric(&range->max_addr.in));
		}
	}
	if (range->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		xt_xlate_add(xl, ":%hu", ntohs(range->min_proto.tcp.port));
		if (range->max_proto.tcp.port != range->min_proto.tcp.port)
			xt_xlate_add(xl, "-%hu", ntohs(range->max_proto.tcp.port));
		if (range->flags & NF_NAT_RANGE_PROTO_OFFSET)
			xt_xlate_add(xl, ";%hu", ntohs(range->base_proto.tcp.port));
	}
}

static int DNAT_xlate_v2(struct xt_xlate *xl,
		      const struct xt_xlate_tg_params *params)
{
	const struct nf_nat_range2 *range = (const void *)params->target->data;
	bool sep_need = false;
	const char *sep = " ";

	xt_xlate_add(xl, "dnat to ");
	print_range_xlate_v2(range, xl);
	if (range->flags & NF_NAT_RANGE_PROTO_RANDOM) {
		xt_xlate_add(xl, " random");
		sep_need = true;
	}
	if (range->flags & NF_NAT_RANGE_PERSISTENT) {
		if (sep_need)
			sep = ",";
		xt_xlate_add(xl, "%spersistent", sep);
	}

	return 1;
}

static struct xtables_target dnat_tg_reg[] = {
	{
		.name		= "DNAT",
		.version	= XTABLES_VERSION,
		.family		= NFPROTO_IPV4,
		.revision	= 0,
		.size		= XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat)),
		.userspacesize	= XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat)),
		.help		= DNAT_help,
		.print		= DNAT_print,
		.save		= DNAT_save,
		.x6_parse	= DNAT_parse,
		.x6_fcheck	= DNAT_fcheck,
		.x6_options	= DNAT_opts,
		.xlate		= DNAT_xlate,
	},
	{
		.name		= "DNAT",
		.version	= XTABLES_VERSION,
		.family		= NFPROTO_IPV4,
		.revision	= 2,
		.size		= XT_ALIGN(sizeof(struct nf_nat_range2)),
		.userspacesize	= XT_ALIGN(sizeof(struct nf_nat_range2)),
		.help		= DNAT_help_v2,
		.print		= DNAT_print_v2,
		.save		= DNAT_save_v2,
		.x6_parse	= DNAT_parse_v2,
		.x6_fcheck	= DNAT_fcheck_v2,
		.x6_options	= DNAT_opts,
		.xlate		= DNAT_xlate_v2,
	},
};

void _init(void)
{
	xtables_register_targets(dnat_tg_reg, ARRAY_SIZE(dnat_tg_reg));
}
