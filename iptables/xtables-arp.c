/* Code to take an arptables-style command line and do it. */

/*
 * arptables:
 * Author: Bart De Schuymer <bdschuym@pandora.be>, but
 * almost all code is from the iptables userspace program, which has main
 * authors: Paul.Russell@rustcorp.com.au and mneuling@radlogic.com.au
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
  Currently, only support for specifying hardware addresses for Ethernet
  is available.
  This tool is not luser-proof: you can specify an Ethernet source address
  and set hardware length to something different than 6, f.e.
*/
#include "config.h"
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <xtables.h>

#include "xshared.h"

#include "nft.h"
#include "nft-arp.h"

static struct option original_opts[] = {
	{ "append", 1, 0, 'A' },
	{ "delete", 1, 0,  'D' },
	{ "check", 1, 0,  'C'},
	{ "insert", 1, 0,  'I' },
	{ "replace", 1, 0,  'R' },
	{ "list", 2, 0,  'L' },
	{ "list-rules", 2, 0,  'S'},
	{ "flush", 2, 0,  'F' },
	{ "zero", 2, 0,  'Z' },
	{ "new-chain", 1, 0,  'N' },
	{ "delete-chain", 2, 0,  'X' },
	{ "rename-chain", 1, 0,  'E' },
	{ "policy", 1, 0,  'P' },
	{ "source-ip", 1, 0, 's' },
	{ "destination-ip", 1, 0,  'd' },
	{ "src-ip", 1, 0,  's' },
	{ "dst-ip", 1, 0,  'd' },
	{ "source-mac", 1, 0, 2},
	{ "destination-mac", 1, 0, 3},
	{ "src-mac", 1, 0, 2},
	{ "dst-mac", 1, 0, 3},
	{ "h-length", 1, 0,  'l' },
	{ "p-length", 1, 0,  8 },
	{ "opcode", 1, 0,  4 },
	{ "h-type", 1, 0,  5 },
	{ "proto-type", 1, 0,  6 },
	{ "in-interface", 1, 0, 'i' },
	{ "jump", 1, 0, 'j' },
	{ "table", 1, 0, 't' },
	{ "match", 1, 0, 'm' },
	{ "numeric", 0, 0, 'n' },
	{ "out-interface", 1, 0, 'o' },
	{ "verbose", 0, 0, 'v' },
	{ "exact", 0, 0, 'x' },
	{ "version", 0, 0, 'V' },
	{ "help", 2, 0, 'h' },
	{ "line-numbers", 0, 0, '0' },
	{ "modprobe", 1, 0, 'M' },
	{ "set-counters", 1, 0, 'c' },
	{ 0 }
};

#define opts xt_params->opts

extern void xtables_exit_error(enum xtables_exittype status, const char *msg, ...) __attribute__((noreturn, format(printf,2,3)));
static void printhelp(const struct xtables_rule_match *m);
struct xtables_globals arptables_globals = {
	.option_offset		= 0,
	.program_version	= PACKAGE_VERSION " (nf_tables)",
	.optstring		= OPTSTRING_COMMON "C:R:S::" "h::l:nv" /* "m:" */,
	.orig_opts		= original_opts,
	.exit_err		= xtables_exit_error,
	.compat_rev		= nft_compatible_revision,
	.print_help		= printhelp,
};

static void
printhelp(const struct xtables_rule_match *m)
{
	struct xtables_target *t = NULL;
	int i;

	printf("%s v%s\n\n"
"Usage: %s -[ACD] chain rule-specification [options]\n"
"       %s -I chain [rulenum] rule-specification [options]\n"
"       %s -R chain rulenum rule-specification [options]\n"
"       %s -D chain rulenum [options]\n"
"       %s -[LS] [chain [rulenum]] [options]\n"
"       %s -[FZ] [chain] [options]\n"
"       %s -[NX] chain\n"
"       %s -E old-chain-name new-chain-name\n"
"       %s -P chain target [options]\n"
"       %s -h (print this help information)\n\n",
	       arptables_globals.program_name,
	       arptables_globals.program_version,
	       arptables_globals.program_name,
	       arptables_globals.program_name,
	       arptables_globals.program_name,
	       arptables_globals.program_name,
	       arptables_globals.program_name,
	       arptables_globals.program_name,
	       arptables_globals.program_name,
	       arptables_globals.program_name,
	       arptables_globals.program_name,
	       arptables_globals.program_name);
	printf(
"Commands:\n"
"Either long or short options are allowed.\n"
"  --append  -A chain		Append to chain\n"
"  --check   -C chain		Check for the existence of a rule\n"
"  --delete  -D chain		Delete matching rule from chain\n"
"  --delete  -D chain rulenum\n"
"				Delete rule rulenum (1 = first) from chain\n"
"  --insert  -I chain [rulenum]\n"
"				Insert in chain as rulenum (default 1=first)\n"
"  --replace -R chain rulenum\n"
"				Replace rule rulenum (1 = first) in chain\n"
"  --list    -L [chain [rulenum]]\n"
"				List the rules in a chain or all chains\n"
"  --list-rules -S [chain [rulenum]]\n"
"				Print the rules in a chain or all chains\n"
"  --flush   -F [chain]		Delete all rules in  chain or all chains\n"
"  --zero    -Z [chain [rulenum]]\n"
"				Zero counters in chain or all chains\n"
"  --new     -N chain		Create a new user-defined chain\n"
"  --delete-chain\n"
"            -X [chain]		Delete a user-defined chain\n"
"  --policy  -P chain target\n"
"				Change policy on chain to target\n"
"  --rename-chain\n"
"            -E old-chain new-chain\n"
"				Change chain name, (moving any references)\n"

"Options:\n"
"  --source-ip	-s [!] address[/mask]\n"
"				source specification\n"
"  --destination-ip -d [!] address[/mask]\n"
"				destination specification\n"
"  --source-mac [!] address[/mask]\n"
"  --destination-mac [!] address[/mask]\n"
"  --h-length   -l   length[/mask] hardware length (nr of bytes)\n"
"  --opcode code[/mask] operation code (2 bytes)\n"
"  --h-type   type[/mask]  hardware type (2 bytes, hexadecimal)\n"
"  --proto-type   type[/mask]  protocol type (2 bytes)\n"
"  --in-interface -i [!] input name[+]\n"
"				network interface name ([+] for wildcard)\n"
"  --out-interface -o [!] output name[+]\n"
"				network interface name ([+] for wildcard)\n"
"  --jump	-j target\n"
"				target for rule (may load target extension)\n"
"  --match	-m match\n"
"				extended match (may load extension)\n"
"  --numeric	-n		numeric output of addresses and ports\n"
"  --table	-t table	table to manipulate (default: `filter')\n"
"  --verbose	-v		verbose mode\n"
"  --line-numbers		print line numbers when listing\n"
"  --exact	-x		expand numbers (display exact values)\n"
"  --modprobe=<command>		try to insert modules using this command\n"
"  --set-counters -c PKTS BYTES	set the counter during insert/append\n"
"[!] --version	-V		print package version.\n");
	printf(" opcode strings: \n");
        for (i = 0; i < NUMOPCODES; i++)
                printf(" %d = %s\n", i + 1, arp_opcodes[i]);
        printf(
" hardware type string: 1 = Ethernet\n"
" protocol type string: 0x800 = IPv4\n");

	/* Print out any special helps. A user might like to be able
		to add a --help to the commandline, and see expected
		results. So we call help for all matches & targets */
	for (t = xtables_targets; t; t = t->next) {
		if (strcmp(t->name, "CLASSIFY") && strcmp(t->name, "mangle"))
			continue;
		printf("\n");
		t->help();
	}
}

int nft_init_arp(struct nft_handle *h, const char *pname)
{
	arptables_globals.program_name = pname;
	if (xtables_init_all(&arptables_globals, NFPROTO_ARP) < 0) {
		fprintf(stderr, "%s/%s Failed to initialize arptables-compat\n",
			arptables_globals.program_name,
			arptables_globals.program_version);
		exit(1);
	}

#if defined(ALL_INCLUSIVE) || defined(NO_SHARED_LIBS)
	init_extensionsa();
#endif

	if (nft_init(h, NFPROTO_ARP) < 0)
		xtables_error(OTHER_PROBLEM,
			      "Could not initialize nftables layer.");

	return 0;
}
