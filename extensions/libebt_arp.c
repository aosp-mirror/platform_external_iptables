/* ebt_arp
 *
 * Authors:
 * Bart De Schuymer <bdschuym@pandora.be>
 * Tim Gardner <timg@tpi.com>
 *
 * April, 2002
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <netinet/ether.h>

#include <xtables.h>
#include <net/if_arp.h>
#include <linux/netfilter_bridge/ebt_arp.h>
#include "iptables/nft.h"
#include "iptables/nft-bridge.h"

#define ARP_OPCODE '1'
#define ARP_HTYPE  '2'
#define ARP_PTYPE  '3'
#define ARP_IP_S   '4'
#define ARP_IP_D   '5'
#define ARP_MAC_S  '6'
#define ARP_MAC_D  '7'
#define ARP_GRAT   '8'

static const struct option brarp_opts[] = {
	{ "arp-opcode"    , required_argument, 0, ARP_OPCODE },
	{ "arp-op"        , required_argument, 0, ARP_OPCODE },
	{ "arp-htype"     , required_argument, 0, ARP_HTYPE  },
	{ "arp-ptype"     , required_argument, 0, ARP_PTYPE  },
	{ "arp-ip-src"    , required_argument, 0, ARP_IP_S   },
	{ "arp-ip-dst"    , required_argument, 0, ARP_IP_D   },
	{ "arp-mac-src"   , required_argument, 0, ARP_MAC_S  },
	{ "arp-mac-dst"   , required_argument, 0, ARP_MAC_D  },
	{ "arp-gratuitous",       no_argument, 0, ARP_GRAT   },
	XT_GETOPT_TABLEEND,
};

/* a few names */
static char *opcodes[] =
{
	"Request",
	"Reply",
	"Request_Reverse",
	"Reply_Reverse",
	"DRARP_Request",
	"DRARP_Reply",
	"DRARP_Error",
	"InARP_Request",
	"ARP_NAK",
};

static void brarp_print_help(void)
{
	int i;

	printf(
"arp options:\n"
"--arp-opcode  [!] opcode        : ARP opcode (integer or string)\n"
"--arp-htype   [!] type          : ARP hardware type (integer or string)\n"
"--arp-ptype   [!] type          : ARP protocol type (hexadecimal or string)\n"
"--arp-ip-src  [!] address[/mask]: ARP IP source specification\n"
"--arp-ip-dst  [!] address[/mask]: ARP IP target specification\n"
"--arp-mac-src [!] address[/mask]: ARP MAC source specification\n"
"--arp-mac-dst [!] address[/mask]: ARP MAC target specification\n"
"[!] --arp-gratuitous            : ARP gratuitous packet\n"
" opcode strings: \n");
	for (i = 0; i < ARRAY_SIZE(opcodes); i++)
		printf(" %d = %s\n", i + 1, opcodes[i]);
	printf(
" hardware type string: 1 = Ethernet\n"
" protocol type string: see "XT_PATH_ETHERTYPES"\n");
}

#define OPT_OPCODE 0x01
#define OPT_HTYPE  0x02
#define OPT_PTYPE  0x04
#define OPT_IP_S   0x08
#define OPT_IP_D   0x10
#define OPT_MAC_S  0x20
#define OPT_MAC_D  0x40
#define OPT_GRAT   0x80

static int
brarp_parse(int c, char **argv, int invert, unsigned int *flags,
	    const void *entry, struct xt_entry_match **match)
{
	struct ebt_arp_info *arpinfo = (struct ebt_arp_info *)(*match)->data;
	struct in_addr *ipaddr, ipmask;
	long int i;
	char *end;
	unsigned char *maddr;
	unsigned char *mmask;
	unsigned int ipnr;

	switch (c) {
	case ARP_OPCODE:
		EBT_CHECK_OPTION(flags, OPT_OPCODE);
		if (invert)
			arpinfo->invflags |= EBT_ARP_OPCODE;
		i = strtol(optarg, &end, 10);
		if (i < 0 || i >= (0x1 << 16) || *end !='\0') {
			for (i = 0; i < ARRAY_SIZE(opcodes); i++)
				if (!strcasecmp(opcodes[i], optarg))
					break;
			if (i == ARRAY_SIZE(opcodes))
				xtables_error(PARAMETER_PROBLEM, "Problem with specified ARP opcode");
			i++;
		}
		arpinfo->opcode = htons(i);
		arpinfo->bitmask |= EBT_ARP_OPCODE;
		break;

	case ARP_HTYPE:
		EBT_CHECK_OPTION(flags, OPT_HTYPE);
		if (invert)
			arpinfo->invflags |= EBT_ARP_HTYPE;
		i = strtol(optarg, &end, 10);
		if (i < 0 || i >= (0x1 << 16) || *end !='\0') {
			if (!strcasecmp("Ethernet", argv[optind - 1]))
				i = 1;
			else
				xtables_error(PARAMETER_PROBLEM, "Problem with specified ARP hardware type");
		}
		arpinfo->htype = htons(i);
		arpinfo->bitmask |= EBT_ARP_HTYPE;
		break;
	case ARP_PTYPE: {
		uint16_t proto;

		EBT_CHECK_OPTION(flags, OPT_PTYPE);
		if (invert)
			arpinfo->invflags |= EBT_ARP_PTYPE;

		i = strtol(optarg, &end, 16);
		if (i < 0 || i >= (0x1 << 16) || *end !='\0') {
			struct xt_ethertypeent *ent;

			ent = xtables_getethertypebyname(argv[optind - 1]);
			if (!ent)
				xtables_error(PARAMETER_PROBLEM, "Problem with specified ARP "
								 "protocol type");
			proto = ent->e_ethertype;

		} else
			proto = i;
		arpinfo->ptype = htons(proto);
		arpinfo->bitmask |= EBT_ARP_PTYPE;
		break;
	}

	case ARP_IP_S:
	case ARP_IP_D:
		xtables_ipparse_any(optarg, &ipaddr, &ipmask, &ipnr);
		if (c == ARP_IP_S) {
			EBT_CHECK_OPTION(flags, OPT_IP_S);
			arpinfo->saddr = ipaddr->s_addr;
			arpinfo->smsk = ipmask.s_addr;
			arpinfo->bitmask |= EBT_ARP_SRC_IP;
		} else {
			EBT_CHECK_OPTION(flags, OPT_IP_D);
			arpinfo->daddr = ipaddr->s_addr;
			arpinfo->dmsk = ipmask.s_addr;
			arpinfo->bitmask |= EBT_ARP_DST_IP;
		}
		free(ipaddr);
		if (invert) {
			if (c == ARP_IP_S)
				arpinfo->invflags |= EBT_ARP_SRC_IP;
			else
				arpinfo->invflags |= EBT_ARP_DST_IP;
		}
		break;
	case ARP_MAC_S:
	case ARP_MAC_D:
		if (c == ARP_MAC_S) {
			EBT_CHECK_OPTION(flags, OPT_MAC_S);
			maddr = arpinfo->smaddr;
			mmask = arpinfo->smmsk;
			arpinfo->bitmask |= EBT_ARP_SRC_MAC;
		} else {
			EBT_CHECK_OPTION(flags, OPT_MAC_D);
			maddr = arpinfo->dmaddr;
			mmask = arpinfo->dmmsk;
			arpinfo->bitmask |= EBT_ARP_DST_MAC;
		}
		if (invert) {
			if (c == ARP_MAC_S)
				arpinfo->invflags |= EBT_ARP_SRC_MAC;
			else
				arpinfo->invflags |= EBT_ARP_DST_MAC;
		}
		if (xtables_parse_mac_and_mask(optarg, maddr, mmask))
			xtables_error(PARAMETER_PROBLEM, "Problem with ARP MAC address argument");
		break;
	case ARP_GRAT:
		EBT_CHECK_OPTION(flags, OPT_GRAT);
		arpinfo->bitmask |= EBT_ARP_GRAT;
		if (invert)
			arpinfo->invflags |= EBT_ARP_GRAT;
		break;
	default:
		return 0;
	}
	return 1;
}

static void brarp_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct ebt_arp_info *arpinfo = (struct ebt_arp_info *)match->data;

	if (arpinfo->bitmask & EBT_ARP_OPCODE) {
		int opcode = ntohs(arpinfo->opcode);
		printf("--arp-op ");
		if (arpinfo->invflags & EBT_ARP_OPCODE)
			printf("! ");
		if (opcode > 0 && opcode <= ARRAY_SIZE(opcodes))
			printf("%s ", opcodes[opcode - 1]);
		else
			printf("%d ", opcode);
	}
	if (arpinfo->bitmask & EBT_ARP_HTYPE) {
		printf("--arp-htype ");
		if (arpinfo->invflags & EBT_ARP_HTYPE)
			printf("! ");
		printf("%d ", ntohs(arpinfo->htype));
	}
	if (arpinfo->bitmask & EBT_ARP_PTYPE) {
		printf("--arp-ptype ");
		if (arpinfo->invflags & EBT_ARP_PTYPE)
			printf("! ");
		printf("0x%x ", ntohs(arpinfo->ptype));
	}
	if (arpinfo->bitmask & EBT_ARP_SRC_IP) {
		printf("--arp-ip-src ");
		if (arpinfo->invflags & EBT_ARP_SRC_IP)
			printf("! ");
		printf("%s%s ", xtables_ipaddr_to_numeric((const struct in_addr*) &arpinfo->saddr),
		       xtables_ipmask_to_numeric((const struct in_addr*)&arpinfo->smsk));
	}
	if (arpinfo->bitmask & EBT_ARP_DST_IP) {
		printf("--arp-ip-dst ");
		if (arpinfo->invflags & EBT_ARP_DST_IP)
			printf("! ");
		printf("%s%s ", xtables_ipaddr_to_numeric((const struct in_addr*) &arpinfo->daddr),
		       xtables_ipmask_to_numeric((const struct in_addr*)&arpinfo->dmsk));
	}
	if (arpinfo->bitmask & EBT_ARP_SRC_MAC) {
		printf("--arp-mac-src ");
		if (arpinfo->invflags & EBT_ARP_SRC_MAC)
			printf("! ");
		xtables_print_mac_and_mask(arpinfo->smaddr, arpinfo->smmsk);
		printf(" ");
	}
	if (arpinfo->bitmask & EBT_ARP_DST_MAC) {
		printf("--arp-mac-dst ");
		if (arpinfo->invflags & EBT_ARP_DST_MAC)
			printf("! ");
		xtables_print_mac_and_mask(arpinfo->dmaddr, arpinfo->dmmsk);
		printf(" ");
	}
	if (arpinfo->bitmask & EBT_ARP_GRAT) {
		if (arpinfo->invflags & EBT_ARP_GRAT)
			printf("! ");
		printf("--arp-gratuitous ");
	}
}

static struct xtables_match brarp_match = {
	.name		= "arp",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_BRIDGE,
	.size		= XT_ALIGN(sizeof(struct ebt_arp_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ebt_arp_info)),
	.help		= brarp_print_help,
	.parse		= brarp_parse,
	.print		= brarp_print,
	.extra_opts	= brarp_opts,
};

void _init(void)
{
	xtables_register_match(&brarp_match);
}
