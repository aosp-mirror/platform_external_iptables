/* Code to take an iptables-style command line and do it. */

/*
 * Author: Paul.Russell@rustcorp.com.au and mneuling@radlogic.com.au
 *
 * (C) 2000-2002 by the netfilter coreteam <coreteam@netfilter.org>:
 *		    Paul 'Rusty' Russell <rusty@rustcorp.com.au>
 *		    Marc Boucher <marc+nf@mbsi.ca>
 *		    James Morris <jmorris@intercode.com.au>
 *		    Harald Welte <laforge@gnumonks.org>
 *		    Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
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
#include "config.h"
#include <getopt.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <iptables.h>
#include <xtables.h>
#include <fcntl.h>
#include "xshared.h"
#include "nft-shared.h"
#include "nft-arp.h"
#include "nft.h"

static struct option original_opts[] = {
	{.name = "append",	  .has_arg = 1, .val = 'A'},
	{.name = "delete",	  .has_arg = 1, .val = 'D'},
	{.name = "check",	  .has_arg = 1, .val = 'C'},
	{.name = "insert",	  .has_arg = 1, .val = 'I'},
	{.name = "replace",	  .has_arg = 1, .val = 'R'},
	{.name = "list",	  .has_arg = 2, .val = 'L'},
	{.name = "list-rules",	  .has_arg = 2, .val = 'S'},
	{.name = "flush",	  .has_arg = 2, .val = 'F'},
	{.name = "zero",	  .has_arg = 2, .val = 'Z'},
	{.name = "new-chain",	  .has_arg = 1, .val = 'N'},
	{.name = "delete-chain",  .has_arg = 2, .val = 'X'},
	{.name = "rename-chain",  .has_arg = 1, .val = 'E'},
	{.name = "policy",	  .has_arg = 1, .val = 'P'},
	{.name = "source",	  .has_arg = 1, .val = 's'},
	{.name = "destination",   .has_arg = 1, .val = 'd'},
	{.name = "src",		  .has_arg = 1, .val = 's'}, /* synonym */
	{.name = "dst",		  .has_arg = 1, .val = 'd'}, /* synonym */
	{.name = "protocol",	  .has_arg = 1, .val = 'p'},
	{.name = "in-interface",  .has_arg = 1, .val = 'i'},
	{.name = "jump",	  .has_arg = 1, .val = 'j'},
	{.name = "table",	  .has_arg = 1, .val = 't'},
	{.name = "match",	  .has_arg = 1, .val = 'm'},
	{.name = "numeric",	  .has_arg = 0, .val = 'n'},
	{.name = "out-interface", .has_arg = 1, .val = 'o'},
	{.name = "verbose",	  .has_arg = 0, .val = 'v'},
	{.name = "wait",	  .has_arg = 2, .val = 'w'},
	{.name = "wait-interval", .has_arg = 2, .val = 'W'},
	{.name = "exact",	  .has_arg = 0, .val = 'x'},
	{.name = "fragments",	  .has_arg = 0, .val = 'f'},
	{.name = "version",	  .has_arg = 0, .val = 'V'},
	{.name = "help",	  .has_arg = 2, .val = 'h'},
	{.name = "line-numbers",  .has_arg = 0, .val = '0'},
	{.name = "modprobe",	  .has_arg = 1, .val = 'M'},
	{.name = "set-counters",  .has_arg = 1, .val = 'c'},
	{.name = "goto",	  .has_arg = 1, .val = 'g'},
	{.name = "ipv4",	  .has_arg = 0, .val = '4'},
	{.name = "ipv6",	  .has_arg = 0, .val = '6'},
	{NULL},
};

struct xtables_globals xtables_globals = {
	.option_offset = 0,
	.program_version = PACKAGE_VERSION " (nf_tables)",
	.optstring = OPTSTRING_COMMON "R:S::W::" "46bfg:h::m:nvw::x",
	.orig_opts = original_opts,
	.compat_rev = nft_compatible_revision,
	.print_help = xtables_printhelp,
};

#define opts xt_params->opts
#define prog_name xt_params->program_name
#define prog_vers xt_params->program_version

/*
 *	All functions starting with "parse" should succeed, otherwise
 *	the program fails.
 *	Most routines return pointers to static data that may change
 *	between calls to the same or other routines with a few exceptions:
 *	"host_to_addr", "parse_hostnetwork", and "parse_hostnetworkmask"
 *	return global static data.
*/

/* Christophe Burki wants `-p 6' to imply `-m tcp'.  */

static int
list_entries(struct nft_handle *h, const char *chain, const char *table,
	     int rulenum, int verbose, int numeric, int expanded,
	     int linenumbers)
{
	unsigned int format;

	format = FMT_OPTIONS;
	if (!verbose)
		format |= FMT_NOCOUNTS;
	else
		format |= FMT_VIA;

	if (numeric)
		format |= FMT_NUMERIC;

	if (!expanded)
		format |= FMT_KILOMEGAGIGA;

	if (linenumbers)
		format |= FMT_LINENUMBERS;

	return nft_cmd_rule_list(h, chain, table, rulenum, format);
}

static int
list_rules(struct nft_handle *h, const char *chain, const char *table,
	   int rulenum, int counters)
{
	if (counters)
	    counters = -1;		/* iptables -c format */

	return nft_cmd_rule_list_save(h, chain, table, rulenum, counters);
}

static void check_empty_interface(struct nft_handle *h, const char *arg)
{
	const char *msg = "Empty interface is likely to be undesired";

	if (*arg != '\0')
		return;

	if (h->family != NFPROTO_ARP)
		xtables_error(PARAMETER_PROBLEM, msg);

	fprintf(stderr, "%s", msg);
}

static void check_inverse(struct nft_handle *h, const char option[],
			  bool *invert, int *optidx, int argc)
{
	switch (h->family) {
	case NFPROTO_ARP:
		break;
	default:
		return;
	}

	if (!option || strcmp(option, "!"))
		return;

	fprintf(stderr, "Using intrapositioned negation (`--option ! this`) "
		"is deprecated in favor of extrapositioned (`! --option this`).\n");

	if (*invert)
		xtables_error(PARAMETER_PROBLEM,
			      "Multiple `!' flags not allowed");
	*invert = true;
	if (optidx) {
		*optidx = *optidx + 1;
		if (argc && *optidx > argc)
			xtables_error(PARAMETER_PROBLEM,
				      "no argument following `!'");
	}
}

void do_parse(struct nft_handle *h, int argc, char *argv[],
	      struct nft_xt_cmd_parse *p, struct iptables_command_state *cs,
	      struct xtables_args *args)
{
	struct xtables_match *m;
	struct xtables_rule_match *matchp;
	bool wait_interval_set = false;
	struct timeval wait_interval;
	struct xtables_target *t;
	bool table_set = false;
	bool invert = false;
	int wait = 0;

	/* re-set optind to 0 in case do_command4 gets called
	 * a second time */
	optind = 0;

	/* clear mflags in case do_command4 gets called a second time
	 * (we clear the global list of all matches for security)*/
	for (m = xtables_matches; m; m = m->next)
		m->mflags = 0;

	for (t = xtables_targets; t; t = t->next) {
		t->tflags = 0;
		t->used = 0;
	}

	/* Suppress error messages: we may add new options if we
	   demand-load a protocol. */
	opterr = 0;

	opts = xt_params->orig_opts;
	while ((cs->c = getopt_long(argc, argv, xt_params->optstring,
					   opts, NULL)) != -1) {
		switch (cs->c) {
			/*
			 * Command selection
			 */
		case 'A':
			add_command(&p->command, CMD_APPEND, CMD_NONE, invert);
			p->chain = optarg;
			break;

		case 'C':
			add_command(&p->command, CMD_CHECK, CMD_NONE, invert);
			p->chain = optarg;
			break;

		case 'D':
			add_command(&p->command, CMD_DELETE, CMD_NONE, invert);
			p->chain = optarg;
			if (xs_has_arg(argc, argv)) {
				p->rulenum = parse_rulenumber(argv[optind++]);
				p->command = CMD_DELETE_NUM;
			}
			break;

		case 'R':
			add_command(&p->command, CMD_REPLACE, CMD_NONE, invert);
			p->chain = optarg;
			if (xs_has_arg(argc, argv))
				p->rulenum = parse_rulenumber(argv[optind++]);
			else
				xtables_error(PARAMETER_PROBLEM,
					   "-%c requires a rule number",
					   cmd2char(CMD_REPLACE));
			break;

		case 'I':
			add_command(&p->command, CMD_INSERT, CMD_NONE, invert);
			p->chain = optarg;
			if (xs_has_arg(argc, argv))
				p->rulenum = parse_rulenumber(argv[optind++]);
			else
				p->rulenum = 1;
			break;

		case 'L':
			add_command(&p->command, CMD_LIST,
				    CMD_ZERO | CMD_ZERO_NUM, invert);
			if (optarg)
				p->chain = optarg;
			else if (xs_has_arg(argc, argv))
				p->chain = argv[optind++];
			if (xs_has_arg(argc, argv))
				p->rulenum = parse_rulenumber(argv[optind++]);
			break;

		case 'S':
			add_command(&p->command, CMD_LIST_RULES,
				    CMD_ZERO|CMD_ZERO_NUM, invert);
			if (optarg)
				p->chain = optarg;
			else if (xs_has_arg(argc, argv))
				p->chain = argv[optind++];
			if (xs_has_arg(argc, argv))
				p->rulenum = parse_rulenumber(argv[optind++]);
			break;

		case 'F':
			add_command(&p->command, CMD_FLUSH, CMD_NONE, invert);
			if (optarg)
				p->chain = optarg;
			else if (xs_has_arg(argc, argv))
				p->chain = argv[optind++];
			break;

		case 'Z':
			add_command(&p->command, CMD_ZERO,
				    CMD_LIST|CMD_LIST_RULES, invert);
			if (optarg)
				p->chain = optarg;
			else if (xs_has_arg(argc, argv))
				p->chain = argv[optind++];
			if (xs_has_arg(argc, argv)) {
				p->rulenum = parse_rulenumber(argv[optind++]);
				p->command = CMD_ZERO_NUM;
			}
			break;

		case 'N':
			parse_chain(optarg);
			add_command(&p->command, CMD_NEW_CHAIN, CMD_NONE,
				    invert);
			p->chain = optarg;
			break;

		case 'X':
			add_command(&p->command, CMD_DELETE_CHAIN, CMD_NONE,
				    invert);
			if (optarg)
				p->chain = optarg;
			else if (xs_has_arg(argc, argv))
				p->chain = argv[optind++];
			break;

		case 'E':
			add_command(&p->command, CMD_RENAME_CHAIN, CMD_NONE,
				    invert);
			p->chain = optarg;
			if (xs_has_arg(argc, argv))
				p->newname = argv[optind++];
			else
				xtables_error(PARAMETER_PROBLEM,
					   "-%c requires old-chain-name and "
					   "new-chain-name",
					    cmd2char(CMD_RENAME_CHAIN));
			break;

		case 'P':
			add_command(&p->command, CMD_SET_POLICY, CMD_NONE,
				    invert);
			p->chain = optarg;
			if (xs_has_arg(argc, argv))
				p->policy = argv[optind++];
			else
				xtables_error(PARAMETER_PROBLEM,
					   "-%c requires a chain and a policy",
					   cmd2char(CMD_SET_POLICY));
			break;

		case 'h':
			if (!optarg)
				optarg = argv[optind];

			/* iptables -p icmp -h */
			if (!cs->matches && cs->protocol)
				xtables_find_match(cs->protocol,
					XTF_TRY_LOAD, &cs->matches);

			xt_params->print_help(cs->matches);
			p->command = CMD_NONE;
			return;

			/*
			 * Option selection
			 */
		case 'p':
			check_inverse(h, optarg, &invert, &optind, argc);
			set_option(&cs->options, OPT_PROTOCOL,
				   &args->invflags, invert);

			/* Canonicalize into lower case */
			for (cs->protocol = argv[optind - 1];
			     *cs->protocol; cs->protocol++)
				*cs->protocol = tolower(*cs->protocol);

			cs->protocol = argv[optind - 1];
			args->proto = xtables_parse_protocol(cs->protocol);

			if (args->proto == 0 &&
			    (args->invflags & XT_INV_PROTO))
				xtables_error(PARAMETER_PROBLEM,
					   "rule would never match protocol");

			/* This needs to happen here to parse extensions */
			if (h->ops->proto_parse)
				h->ops->proto_parse(cs, args);
			break;

		case 's':
			check_inverse(h, optarg, &invert, &optind, argc);
			set_option(&cs->options, OPT_SOURCE,
				   &args->invflags, invert);
			args->shostnetworkmask = argv[optind - 1];
			break;

		case 'd':
			check_inverse(h, optarg, &invert, &optind, argc);
			set_option(&cs->options, OPT_DESTINATION,
				   &args->invflags, invert);
			args->dhostnetworkmask = argv[optind - 1];
			break;

#ifdef IPT_F_GOTO
		case 'g':
			set_option(&cs->options, OPT_JUMP, &args->invflags,
				   invert);
			args->goto_set = true;
			cs->jumpto = xt_parse_target(optarg);
			break;
#endif

		case 2:/* src-mac */
			check_inverse(h, optarg, &invert, &optind, argc);
			set_option(&cs->options, OPT_S_MAC, &args->invflags,
				   invert);
			args->src_mac = argv[optind - 1];
			break;

		case 3:/* dst-mac */
			check_inverse(h, optarg, &invert, &optind, argc);
			set_option(&cs->options, OPT_D_MAC, &args->invflags,
				   invert);
			args->dst_mac = argv[optind - 1];
			break;

		case 'l':/* hardware length */
			check_inverse(h, optarg, &invert, &optind, argc);
			set_option(&cs->options, OPT_H_LENGTH, &args->invflags,
				   invert);
			args->arp_hlen = argv[optind - 1];
			break;

		case 8: /* was never supported, not even in arptables-legacy */
			xtables_error(PARAMETER_PROBLEM, "not supported");
		case 4:/* opcode */
			check_inverse(h, optarg, &invert, &optind, argc);
			set_option(&cs->options, OPT_OPCODE, &args->invflags,
				   invert);
			args->arp_opcode = argv[optind - 1];
			break;

		case 5:/* h-type */
			check_inverse(h, optarg, &invert, &optind, argc);
			set_option(&cs->options, OPT_H_TYPE, &args->invflags,
				   invert);
			args->arp_htype = argv[optind - 1];
			break;

		case 6:/* proto-type */
			check_inverse(h, optarg, &invert, &optind, argc);
			set_option(&cs->options, OPT_P_TYPE, &args->invflags,
				   invert);
			args->arp_ptype = argv[optind - 1];
			break;

		case 'j':
			set_option(&cs->options, OPT_JUMP, &args->invflags,
				   invert);
			command_jump(cs, argv[optind - 1]);
			break;

		case 'i':
			check_empty_interface(h, optarg);
			check_inverse(h, optarg, &invert, &optind, argc);
			set_option(&cs->options, OPT_VIANAMEIN,
				   &args->invflags, invert);
			xtables_parse_interface(argv[optind - 1],
						args->iniface,
						args->iniface_mask);
			break;

		case 'o':
			check_empty_interface(h, optarg);
			check_inverse(h, optarg, &invert, &optind, argc);
			set_option(&cs->options, OPT_VIANAMEOUT,
				   &args->invflags, invert);
			xtables_parse_interface(argv[optind - 1],
						args->outiface,
						args->outiface_mask);
			break;

		case 'f':
			if (args->family == AF_INET6) {
				xtables_error(PARAMETER_PROBLEM,
					"`-f' is not supported in IPv6, "
					"use -m frag instead");
			}
			set_option(&cs->options, OPT_FRAGMENT, &args->invflags,
				   invert);
			args->flags |= IPT_F_FRAG;
			break;

		case 'v':
			if (!p->verbose)
				set_option(&cs->options, OPT_VERBOSE,
					   &args->invflags, invert);
			p->verbose++;
			break;

		case 'm':
			command_match(cs, invert);
			break;

		case 'n':
			set_option(&cs->options, OPT_NUMERIC, &args->invflags,
				   invert);
			break;

		case 't':
			if (invert)
				xtables_error(PARAMETER_PROBLEM,
					   "unexpected ! flag before --table");
			if (p->restore && table_set)
				xtables_error(PARAMETER_PROBLEM,
					      "The -t option cannot be used in %s.\n",
					      xt_params->program_name);
			p->table = optarg;
			table_set = true;
			break;

		case 'x':
			set_option(&cs->options, OPT_EXPANDED, &args->invflags,
				   invert);
			break;

		case 'V':
			if (invert)
				printf("Not %s ;-)\n", prog_vers);
			else
				printf("%s v%s\n",
				       prog_name, prog_vers);
			exit(0);

		case 'w':
			if (p->restore) {
				xtables_error(PARAMETER_PROBLEM,
					      "You cannot use `-w' from "
					      "iptables-restore");
			}

			wait = parse_wait_time(argc, argv);
			break;

		case 'W':
			if (p->restore) {
				xtables_error(PARAMETER_PROBLEM,
					      "You cannot use `-W' from "
					      "iptables-restore");
			}

			parse_wait_interval(argc, argv, &wait_interval);
			wait_interval_set = true;
			break;

		case '0':
			set_option(&cs->options, OPT_LINENUMBERS,
				   &args->invflags, invert);
			break;

		case 'M':
			xtables_modprobe_program = optarg;
			break;

		case 'c':
			set_option(&cs->options, OPT_COUNTERS, &args->invflags,
				   invert);
			args->pcnt = optarg;
			args->bcnt = strchr(args->pcnt + 1, ',');
			if (args->bcnt)
			    args->bcnt++;
			if (!args->bcnt && xs_has_arg(argc, argv))
				args->bcnt = argv[optind++];
			if (!args->bcnt)
				xtables_error(PARAMETER_PROBLEM,
					"-%c requires packet and byte counter",
					opt2char(OPT_COUNTERS));

			if (sscanf(args->pcnt, "%llu", &args->pcnt_cnt) != 1)
				xtables_error(PARAMETER_PROBLEM,
					"-%c packet counter not numeric",
					opt2char(OPT_COUNTERS));

			if (sscanf(args->bcnt, "%llu", &args->bcnt_cnt) != 1)
				xtables_error(PARAMETER_PROBLEM,
					"-%c byte counter not numeric",
					opt2char(OPT_COUNTERS));
			break;

		case '4':
			if (args->family == AF_INET)
				break;

			if (p->restore && args->family == AF_INET6)
				return;

			exit_tryhelp(2, line);

		case '6':
			if (args->family == AF_INET6)
				break;

			if (p->restore && args->family == AF_INET)
				return;

			exit_tryhelp(2, line);

		case 1: /* non option */
			if (optarg[0] == '!' && optarg[1] == '\0') {
				if (invert)
					xtables_error(PARAMETER_PROBLEM,
						   "multiple consecutive ! not"
						   " allowed");
				invert = true;
				optarg[0] = '\0';
				continue;
			}
			fprintf(stderr, "Bad argument `%s'\n", optarg);
			exit_tryhelp(2, line);

		default:
			if (command_default(cs, xt_params, invert))
				/* cf. ip6tables.c */
				continue;
			break;
		}
		invert = false;
	}

	if (strcmp(p->table, "nat") == 0 &&
	    ((p->policy != NULL && strcmp(p->policy, "DROP") == 0) ||
	    (cs->jumpto != NULL && strcmp(cs->jumpto, "DROP") == 0)))
		xtables_error(PARAMETER_PROBLEM,
			"\nThe \"nat\" table is not intended for filtering, "
			"the use of DROP is therefore inhibited.\n\n");

	if (!wait && wait_interval_set)
		xtables_error(PARAMETER_PROBLEM,
			      "--wait-interval only makes sense with --wait\n");

	for (matchp = cs->matches; matchp; matchp = matchp->next)
		xtables_option_mfcall(matchp->match);
	if (cs->target != NULL)
		xtables_option_tfcall(cs->target);

	/* Fix me: must put inverse options checking here --MN */

	if (optind < argc)
		xtables_error(PARAMETER_PROBLEM,
			   "unknown arguments found on commandline");
	if (!p->command)
		xtables_error(PARAMETER_PROBLEM, "no command specified");
	if (invert)
		xtables_error(PARAMETER_PROBLEM,
			   "nothing appropriate following !");

	h->ops->post_parse(p->command, cs, args);

	if (p->command == CMD_REPLACE &&
	    (args->s.naddrs != 1 || args->d.naddrs != 1))
		xtables_error(PARAMETER_PROBLEM, "Replacement rule does not "
			   "specify a unique address");

	generic_opt_check(p->command, cs->options);

	if (p->chain != NULL && strlen(p->chain) >= XT_EXTENSION_MAXNAMELEN)
		xtables_error(PARAMETER_PROBLEM,
			   "chain name `%s' too long (must be under %u chars)",
			   p->chain, XT_EXTENSION_MAXNAMELEN);

	if (p->command == CMD_APPEND ||
	    p->command == CMD_DELETE ||
	    p->command == CMD_DELETE_NUM ||
	    p->command == CMD_CHECK ||
	    p->command == CMD_INSERT ||
	    p->command == CMD_REPLACE) {
		if (strcmp(p->chain, "PREROUTING") == 0
		    || strcmp(p->chain, "INPUT") == 0) {
			/* -o not valid with incoming packets. */
			if (cs->options & OPT_VIANAMEOUT)
				xtables_error(PARAMETER_PROBLEM,
					   "Can't use -%c with %s\n",
					   opt2char(OPT_VIANAMEOUT),
					   p->chain);
		}

		if (strcmp(p->chain, "POSTROUTING") == 0
		    || strcmp(p->chain, "OUTPUT") == 0) {
			/* -i not valid with outgoing packets */
			if (cs->options & OPT_VIANAMEIN)
				xtables_error(PARAMETER_PROBLEM,
					   "Can't use -%c with %s\n",
					   opt2char(OPT_VIANAMEIN),
					   p->chain);
		}
	}
}

int do_commandx(struct nft_handle *h, int argc, char *argv[], char **table,
		bool restore)
{
	int ret = 1;
	struct nft_xt_cmd_parse p = {
		.table		= *table,
		.restore	= restore,
	};
	struct iptables_command_state cs = {
		.jumpto = "",
		.argv = argv,
	};
	struct xtables_args args = {
		.family = h->family,
	};

	if (h->ops->init_cs)
		h->ops->init_cs(&cs);

	do_parse(h, argc, argv, &p, &cs, &args);

	if (!nft_table_builtin_find(h, p.table))
		xtables_error(VERSION_PROBLEM,
			      "table '%s' does not exist",
			      p.table);
	switch (p.command) {
	case CMD_APPEND:
		ret = h->ops->add_entry(h, p.chain, p.table, &cs, &args,
					cs.options & OPT_VERBOSE, true,
					p.rulenum - 1);
		break;
	case CMD_DELETE:
		ret = h->ops->delete_entry(h, p.chain, p.table, &cs, &args,
					   cs.options & OPT_VERBOSE);
		break;
	case CMD_DELETE_NUM:
		ret = nft_cmd_rule_delete_num(h, p.chain, p.table,
					      p.rulenum - 1, p.verbose);
		break;
	case CMD_CHECK:
		ret = h->ops->check_entry(h, p.chain, p.table, &cs, &args,
					  cs.options & OPT_VERBOSE);
		break;
	case CMD_REPLACE:
		ret = h->ops->replace_entry(h, p.chain, p.table, &cs, &args,
					    cs.options & OPT_VERBOSE,
					    p.rulenum - 1);
		break;
	case CMD_INSERT:
		ret = h->ops->add_entry(h, p.chain, p.table, &cs, &args,
					cs.options & OPT_VERBOSE, false,
					p.rulenum - 1);
		break;
	case CMD_FLUSH:
		ret = nft_cmd_rule_flush(h, p.chain, p.table,
					 cs.options & OPT_VERBOSE);
		break;
	case CMD_ZERO:
		ret = nft_cmd_chain_zero_counters(h, p.chain, p.table,
						  cs.options & OPT_VERBOSE);
		break;
	case CMD_ZERO_NUM:
		ret = nft_cmd_rule_zero_counters(h, p.chain, p.table,
					     p.rulenum - 1);
		break;
	case CMD_LIST:
	case CMD_LIST|CMD_ZERO:
	case CMD_LIST|CMD_ZERO_NUM:
		ret = list_entries(h, p.chain, p.table, p.rulenum,
				   cs.options & OPT_VERBOSE,
				   cs.options & OPT_NUMERIC,
				   cs.options & OPT_EXPANDED,
				   cs.options & OPT_LINENUMBERS);
		if (ret && (p.command & CMD_ZERO)) {
			ret = nft_cmd_chain_zero_counters(h, p.chain, p.table,
						      cs.options & OPT_VERBOSE);
		}
		if (ret && (p.command & CMD_ZERO_NUM)) {
			ret = nft_cmd_rule_zero_counters(h, p.chain, p.table,
						     p.rulenum - 1);
		}
		nft_check_xt_legacy(h->family, false);
		break;
	case CMD_LIST_RULES:
	case CMD_LIST_RULES|CMD_ZERO:
	case CMD_LIST_RULES|CMD_ZERO_NUM:
		ret = list_rules(h, p.chain, p.table, p.rulenum,
				 cs.options & OPT_VERBOSE);
		if (ret && (p.command & CMD_ZERO)) {
			ret = nft_cmd_chain_zero_counters(h, p.chain, p.table,
						      cs.options & OPT_VERBOSE);
		}
		if (ret && (p.command & CMD_ZERO_NUM)) {
			ret = nft_cmd_rule_zero_counters(h, p.chain, p.table,
						     p.rulenum - 1);
		}
		nft_check_xt_legacy(h->family, false);
		break;
	case CMD_NEW_CHAIN:
		ret = nft_cmd_chain_user_add(h, p.chain, p.table);
		break;
	case CMD_DELETE_CHAIN:
		ret = nft_cmd_chain_del(h, p.chain, p.table,
					cs.options & OPT_VERBOSE);
		break;
	case CMD_RENAME_CHAIN:
		ret = nft_cmd_chain_user_rename(h, p.chain, p.table, p.newname);
		break;
	case CMD_SET_POLICY:
		ret = nft_cmd_chain_set(h, p.table, p.chain, p.policy, NULL);
		break;
	case CMD_NONE:
	/* do_parse ignored the line (eg: -4 with ip6tables-restore) */
		break;
	default:
		/* We should never reach this... */
		exit_tryhelp(2, line);
	}

	*table = p.table;

	nft_clear_iptables_command_state(&cs);

	free(args.s.addr.ptr);
	free(args.s.mask.ptr);
	free(args.d.addr.ptr);
	free(args.d.mask.ptr);
	xtables_free_opts(1);

	return ret;
}
