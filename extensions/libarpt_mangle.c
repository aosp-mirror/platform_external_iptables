/*
 * Arturo Borrero Gonzalez <arturo@debian.org> adapted
 * this code to libxtables for arptables-compat in 2015
 */

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <getopt.h>
#include <netinet/ether.h>
#include <xtables.h>
#include <linux/netfilter_arp/arpt_mangle.h>
#include "iptables/nft.h"

static void arpmangle_print_help(void)
{
	printf(
	"mangle target options:\n"
	"--mangle-ip-s IP address\n"
	"--mangle-ip-d IP address\n"
	"--mangle-mac-s MAC address\n"
	"--mangle-mac-d MAC address\n"
	"--mangle-target target (DROP, CONTINUE or ACCEPT -- default is ACCEPT)\n");
}

#define MANGLE_IPS    '1'
#define MANGLE_IPT    '2'
#define MANGLE_DEVS   '3'
#define MANGLE_DEVT   '4'
#define MANGLE_TARGET '5'

static const struct option arpmangle_opts[] = {
	{ .name = "mangle-ip-s",	.has_arg = true, .val = MANGLE_IPS },
	{ .name = "mangle-ip-d",	.has_arg = true, .val = MANGLE_IPT },
	{ .name = "mangle-mac-s",	.has_arg = true, .val = MANGLE_DEVS },
	{ .name = "mangle-mac-d",	.has_arg = true, .val = MANGLE_DEVT },
	{ .name = "mangle-target",	.has_arg = true, .val = MANGLE_TARGET },
	XT_GETOPT_TABLEEND,
};

static void arpmangle_init(struct xt_entry_target *target)
{
	struct arpt_mangle *mangle = (struct arpt_mangle *)target->data;

	mangle->target = NF_ACCEPT;
}

static int
arpmangle_parse(int c, char **argv, int invert, unsigned int *flags,
		const void *entry, struct xt_entry_target **target)
{
	struct arpt_mangle *mangle = (struct arpt_mangle *)(*target)->data;
	struct in_addr *ipaddr, mask;
	struct ether_addr *macaddr;
	const struct arpt_entry *e = (const struct arpt_entry *)entry;
	unsigned int nr;
	int ret = 1;

	memset(&mask, 0, sizeof(mask));

	switch (c) {
	case MANGLE_IPS:
		xtables_ipparse_any(optarg, &ipaddr, &mask, &nr);
		mangle->u_s.src_ip.s_addr = ipaddr->s_addr;
		free(ipaddr);
		mangle->flags |= ARPT_MANGLE_SIP;
		break;
	case MANGLE_IPT:
		xtables_ipparse_any(optarg, &ipaddr, &mask, &nr);
		mangle->u_t.tgt_ip.s_addr = ipaddr->s_addr;
		free(ipaddr);
		mangle->flags |= ARPT_MANGLE_TIP;
		break;
	case MANGLE_DEVS:
		if (e->arp.arhln_mask == 0)
			xtables_error(PARAMETER_PROBLEM,
				      "no --h-length defined");
		if (e->arp.invflags & IPT_INV_ARPHLN)
			xtables_error(PARAMETER_PROBLEM,
				      "! --h-length not allowed for "
				      "--mangle-mac-s");
		if (e->arp.arhln != 6)
			xtables_error(PARAMETER_PROBLEM,
				      "only --h-length 6 supported");
		macaddr = ether_aton(optarg);
		if (macaddr == NULL)
			xtables_error(PARAMETER_PROBLEM,
				      "invalid source MAC");
		memcpy(mangle->src_devaddr, macaddr, e->arp.arhln);
		mangle->flags |= ARPT_MANGLE_SDEV;
		break;
	case MANGLE_DEVT:
		if (e->arp.arhln_mask == 0)
			xtables_error(PARAMETER_PROBLEM,
				      "no --h-length defined");
		if (e->arp.invflags & IPT_INV_ARPHLN)
			xtables_error(PARAMETER_PROBLEM,
				      "! hln not allowed for --mangle-mac-d");
		if (e->arp.arhln != 6)
			xtables_error(PARAMETER_PROBLEM,
				      "only --h-length 6 supported");
		macaddr = ether_aton(optarg);
		if (macaddr == NULL)
			xtables_error(PARAMETER_PROBLEM, "invalid target MAC");
		memcpy(mangle->tgt_devaddr, macaddr, e->arp.arhln);
		mangle->flags |= ARPT_MANGLE_TDEV;
		break;
	case MANGLE_TARGET:
		if (!strcmp(optarg, "DROP"))
			mangle->target = NF_DROP;
		else if (!strcmp(optarg, "ACCEPT"))
			mangle->target = NF_ACCEPT;
		else if (!strcmp(optarg, "CONTINUE"))
			mangle->target = XT_CONTINUE;
		else
			xtables_error(PARAMETER_PROBLEM,
				      "bad target for --mangle-target");
		break;
	default:
		ret = 0;
	}

	return ret;
}

static void arpmangle_final_check(unsigned int flags)
{
}

static const char *ipaddr_to(const struct in_addr *addrp, int numeric)
{
	if (numeric)
		return xtables_ipaddr_to_numeric(addrp);
	else
		return xtables_ipaddr_to_anyname(addrp);
}

static void
arpmangle_print(const void *ip, const struct xt_entry_target *target,
		int numeric)
{
	struct arpt_mangle *m = (struct arpt_mangle *)(target->data);

	if (m->flags & ARPT_MANGLE_SIP) {
		printf(" --mangle-ip-s %s",
		       ipaddr_to(&(m->u_s.src_ip), numeric));
	}
	if (m->flags & ARPT_MANGLE_SDEV) {
		printf(" --mangle-mac-s ");
		xtables_print_mac((unsigned char *)m->src_devaddr);
	}
	if (m->flags & ARPT_MANGLE_TIP) {
		printf(" --mangle-ip-d %s",
		       ipaddr_to(&(m->u_t.tgt_ip), numeric));
	}
	if (m->flags & ARPT_MANGLE_TDEV) {
		printf(" --mangle-mac-d ");
		xtables_print_mac((unsigned char *)m->tgt_devaddr);
	}
	if (m->target != NF_ACCEPT) {
		printf(" --mangle-target %s",
		       m->target == NF_DROP ? "DROP" : "CONTINUE");
	}
}

static void arpmangle_save(const void *ip, const struct xt_entry_target *target)
{
	arpmangle_print(ip, target, 0);
}

static void print_devaddr_xlate(const char *macaddress, struct xt_xlate *xl)
{
	unsigned int i;

	xt_xlate_add(xl, "%02x", macaddress[0]);
	for (i = 1; i < ETH_ALEN; ++i)
		xt_xlate_add(xl, ":%02x", macaddress[i]);
}

static int arpmangle_xlate(struct xt_xlate *xl,
			 const struct xt_xlate_tg_params *params)
{
	const struct arpt_mangle *m = (const void *)params->target->data;

	if (m->flags & ARPT_MANGLE_SIP)
		xt_xlate_add(xl, "arp saddr ip set %s ",
			     xtables_ipaddr_to_numeric(&m->u_s.src_ip));

	if (m->flags & ARPT_MANGLE_SDEV) {
		xt_xlate_add(xl, "arp %caddr ether set ", 's');
		print_devaddr_xlate(m->src_devaddr, xl);
	}

	if (m->flags & ARPT_MANGLE_TIP)
		xt_xlate_add(xl, "arp daddr ip set %s ",
			     xtables_ipaddr_to_numeric(&m->u_t.tgt_ip));

	if (m->flags & ARPT_MANGLE_TDEV) {
		xt_xlate_add(xl, "arp %caddr ether set ", 'd');
		print_devaddr_xlate(m->tgt_devaddr, xl);
	}

	switch (m->target) {
	case NF_ACCEPT:
		xt_xlate_add(xl, "accept");
		break;
	case NF_DROP:
		xt_xlate_add(xl, "drop");
		break;
	default:
		break;
	}

	return 1;
}

static struct xtables_target arpmangle_target = {
	.name		= "mangle",
	.revision	= 0,
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_ARP,
	.size		= XT_ALIGN(sizeof(struct arpt_mangle)),
	.userspacesize	= XT_ALIGN(sizeof(struct arpt_mangle)),
	.help		= arpmangle_print_help,
	.init		= arpmangle_init,
	.parse		= arpmangle_parse,
	.final_check	= arpmangle_final_check,
	.print		= arpmangle_print,
	.save		= arpmangle_save,
	.extra_opts	= arpmangle_opts,
	.xlate		= arpmangle_xlate,
};

void _init(void)
{
	xtables_register_target(&arpmangle_target);
}
