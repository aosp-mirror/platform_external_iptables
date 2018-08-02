/* Code to restore the iptables state, from file by iptables-save.
 * (C) 2000-2002 by Harald Welte <laforge@gnumonks.org>
 * based on previous code from Rusty Russell <rusty@linuxcare.com.au>
 *
 * This code is distributed under the terms of GNU GPL v2
 */

#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "iptables.h"
#include "xtables.h"
#include "libiptc/libiptc.h"
#include "xtables-multi.h"
#include "nft.h"
#include "nft-bridge.h"
#include <libnftnl/chain.h>

static int counters, verbose, noflush;

/* Keeping track of external matches and targets.  */
static const struct option options[] = {
	{.name = "counters", .has_arg = false, .val = 'c'},
	{.name = "verbose",  .has_arg = false, .val = 'v'},
	{.name = "version",       .has_arg = 0, .val = 'V'},
	{.name = "test",     .has_arg = false, .val = 't'},
	{.name = "help",     .has_arg = false, .val = 'h'},
	{.name = "noflush",  .has_arg = false, .val = 'n'},
	{.name = "modprobe", .has_arg = true,  .val = 'M'},
	{.name = "table",    .has_arg = true,  .val = 'T'},
	{.name = "ipv4",     .has_arg = false, .val = '4'},
	{.name = "ipv6",     .has_arg = false, .val = '6'},
	{.name = "wait",          .has_arg = 2, .val = 'w'},
	{.name = "wait-interval", .has_arg = 2, .val = 'W'},
	{NULL},
};

#define prog_name xtables_globals.program_name
#define prog_vers xtables_globals.program_version

static void print_usage(const char *name, const char *version)
{
	fprintf(stderr, "Usage: %s [-c] [-v] [-V] [-t] [-h] [-n] [-T table] [-M command] [-4] [-6]\n"
			"	   [ --counters ]\n"
			"	   [ --verbose ]\n"
			"	   [ --version]\n"
			"	   [ --test ]\n"
			"	   [ --help ]\n"
			"	   [ --noflush ]\n"
			"	   [ --table=<TABLE> ]\n"
			"          [ --modprobe=<command> ]\n"
			"	   [ --ipv4 ]\n"
			"	   [ --ipv6 ]\n", name);
}

static struct nftnl_chain_list *get_chain_list(struct nft_handle *h)
{
	struct nftnl_chain_list *chain_list;

	chain_list = nft_chain_dump(h);
	if (chain_list == NULL)
		xtables_error(OTHER_PROBLEM, "cannot retrieve chain list\n");

	return chain_list;
}

static void chain_delete(struct nftnl_chain_list *clist, const char *curtable,
			 const char *chain)
{
	struct nftnl_chain *chain_obj;

	chain_obj = nft_chain_list_find(clist, curtable, chain);
	/* This chain has been found, delete from list. Later
	 * on, unvisited chains will be purged out.
	 */
	if (chain_obj != NULL) {
		nftnl_chain_list_del(chain_obj);
		nftnl_chain_free(chain_obj);
	}
}

struct nft_xt_restore_cb restore_cb = {
	.chain_list	= get_chain_list,
	.commit		= nft_commit,
	.abort		= nft_abort,
	.table_new	= nft_table_new,
	.table_flush	= nft_table_flush,
	.chain_user_flush = nft_chain_user_flush,
	.chain_del	= chain_delete,
	.do_command	= do_commandx,
	.chain_set	= nft_chain_set,
	.chain_user_add	= nft_chain_user_add,
};

static const struct xtc_ops xtc_ops = {
	.strerror	= nft_strerror,
};

void xtables_restore_parse(struct nft_handle *h,
			   struct nft_xt_restore_parse *p,
			   struct nft_xt_restore_cb *cb,
			   int argc, char *argv[])
{
	char buffer[10240];
	int in_table = 0;
	char curtable[XT_TABLE_MAXNAMELEN + 1];
	const struct xtc_ops *ops = &xtc_ops;
	struct nftnl_chain_list *chain_list = NULL;

	line = 0;

	if (cb->chain_list)
		chain_list = cb->chain_list(h);

	/* Grab standard input. */
	while (fgets(buffer, sizeof(buffer), p->in)) {
		int ret = 0;

		line++;
		h->error.lineno = line;

		if (buffer[0] == '\n')
			continue;
		else if (buffer[0] == '#') {
			if (verbose)
				fputs(buffer, stdout);
			continue;
		} else if ((strcmp(buffer, "COMMIT\n") == 0) && (in_table)) {
			if (!p->testing) {
				/* Commit per table, although we support
				 * global commit at once, stick by now to
				 * the existing behaviour.
				 */
				DEBUGP("Calling commit\n");
				if (cb->commit)
					ret = cb->commit(h);
			} else {
				DEBUGP("Not calling commit, testing\n");
				if (cb->abort)
					ret = cb->abort(h);
			}
			in_table = 0;

		} else if ((buffer[0] == '*') && (!in_table)) {
			/* New table */
			char *table;

			table = strtok(buffer+1, " \t\n");
			DEBUGP("line %u, table '%s'\n", line, table);
			if (!table) {
				xtables_error(PARAMETER_PROBLEM,
					"%s: line %u table name invalid\n",
					xt_params->program_name, line);
				exit(1);
			}
			strncpy(curtable, table, XT_TABLE_MAXNAMELEN);
			curtable[XT_TABLE_MAXNAMELEN] = '\0';

			if (p->tablename && (strcmp(p->tablename, table) != 0))
				continue;

			if (noflush == 0) {
				DEBUGP("Cleaning all chains of table '%s'\n",
					table);
				if (cb->table_flush)
					cb->table_flush(h, table);
			}

			ret = 1;
			in_table = 1;

			if (cb->table_new)
				cb->table_new(h, table);

		} else if ((buffer[0] == ':') && (in_table)) {
			/* New chain. */
			char *policy, *chain = NULL;
			struct xt_counters count = {};

			chain = strtok(buffer+1, " \t\n");
			DEBUGP("line %u, chain '%s'\n", line, chain);
			if (!chain) {
				xtables_error(PARAMETER_PROBLEM,
					   "%s: line %u chain name invalid\n",
					   xt_params->program_name, line);
				exit(1);
			}

			if (noflush == 0) {
				if (cb->chain_del)
					cb->chain_del(chain_list, curtable,
						      chain);
			} else {
				/* Apparently -n still flushes existing user
				 * defined chains that are redefined. Otherwise,
				 * leave them as is.
				 */
				if (cb->chain_user_flush)
					cb->chain_user_flush(h, chain_list,
							     curtable, chain);
			}

			if (strlen(chain) >= XT_EXTENSION_MAXNAMELEN)
				xtables_error(PARAMETER_PROBLEM,
					   "Invalid chain name `%s' "
					   "(%u chars max)",
					   chain, XT_EXTENSION_MAXNAMELEN - 1);

			policy = strtok(NULL, " \t\n");
			DEBUGP("line %u, policy '%s'\n", line, policy);
			if (!policy) {
				xtables_error(PARAMETER_PROBLEM,
					   "%s: line %u policy invalid\n",
					   xt_params->program_name, line);
				exit(1);
			}

			if (strcmp(policy, "-") != 0) {
				if (counters) {
					char *ctrs;
					ctrs = strtok(NULL, " \t\n");

					if (!ctrs || !parse_counters(ctrs, &count))
						xtables_error(PARAMETER_PROBLEM,
							   "invalid policy counters "
							   "for chain '%s'\n", chain);

				}
				if (cb->chain_set &&
				    cb->chain_set(h, curtable, chain, policy, &count) < 0) {
					xtables_error(OTHER_PROBLEM,
						      "Can't set policy `%s'"
						      " on `%s' line %u: %s\n",
						      policy, chain, line,
						      ops->strerror(errno));
				}
				DEBUGP("Setting policy of chain %s to %s\n",
				       chain, policy);
				ret = 1;

			} else {
				if (cb->chain_user_add &&
				    cb->chain_user_add(h, chain, curtable) < 0) {
					if (errno == EEXIST)
						continue;

					xtables_error(PARAMETER_PROBLEM,
						      "cannot create chain "
						      "'%s' (%s)\n", chain,
						      strerror(errno));
				}
				continue;
			}

		} else if (in_table) {
			int a;
			char *ptr = buffer;
			char *pcnt = NULL;
			char *bcnt = NULL;
			char *parsestart;

			/* reset the newargv */
			newargc = 0;

			if (buffer[0] == '[') {
				/* we have counters in our input */
				ptr = strchr(buffer, ']');
				if (!ptr)
					xtables_error(PARAMETER_PROBLEM,
						   "Bad line %u: need ]\n",
						   line);

				pcnt = strtok(buffer+1, ":");
				if (!pcnt)
					xtables_error(PARAMETER_PROBLEM,
						   "Bad line %u: need :\n",
						   line);

				bcnt = strtok(NULL, "]");
				if (!bcnt)
					xtables_error(PARAMETER_PROBLEM,
						   "Bad line %u: need ]\n",
						   line);

				/* start command parsing after counter */
				parsestart = ptr + 1;
			} else {
				/* start command parsing at start of line */
				parsestart = buffer;
			}

			add_argv(argv[0], 0);
			add_argv("-t", 0);
			add_argv(curtable, 0);

			if (counters && pcnt && bcnt) {
				add_argv("--set-counters", 0);
				add_argv((char *) pcnt, 0);
				add_argv((char *) bcnt, 0);
			}

			add_param_to_argv(parsestart, line);

			DEBUGP("calling do_command4(%u, argv, &%s, handle):\n",
				newargc, curtable);

			for (a = 0; a < newargc; a++)
				DEBUGP("argv[%u]: %s\n", a, newargv[a]);

			ret = cb->do_command(h, newargc, newargv,
					    &newargv[2], true);
			if (ret < 0) {
				if (cb->abort)
					ret = cb->abort(h);
				else
					ret = 0;

				if (ret < 0) {
					fprintf(stderr, "failed to abort "
							"commit operation\n");
				}
				exit(1);
			}

			free_argv();
			fflush(stdout);
		}
		if (p->tablename && (strcmp(p->tablename, curtable) != 0))
			continue;
		if (!ret) {
			fprintf(stderr, "%s: line %u failed\n",
					xt_params->program_name, line);
			exit(1);
		}
	}
	if (in_table) {
		fprintf(stderr, "%s: COMMIT expected at line %u\n",
				xt_params->program_name, line + 1);
		exit(1);
	}
}

static int
xtables_restore_main(int family, const char *progname, int argc, char *argv[])
{
	struct builtin_table *tables;
	struct nft_handle h = {
		.family = family,
		.restore = true,
	};
	int c;
	struct nft_xt_restore_parse p = {};

	line = 0;

	xtables_globals.program_name = progname;
	c = xtables_init_all(&xtables_globals, family);
	if (c < 0) {
		fprintf(stderr, "%s/%s Failed to initialize xtables\n",
				xtables_globals.program_name,
				xtables_globals.program_version);
		exit(1);
	}

	while ((c = getopt_long(argc, argv, "bcvVthnM:T:46wW", options, NULL)) != -1) {
		switch (c) {
			case 'b':
				fprintf(stderr, "-b/--binary option is not implemented\n");
				break;
			case 'c':
				counters = 1;
				break;
			case 'v':
				verbose = 1;
				break;
			case 'V':
				printf("%s v%s (nf_tables)\n", prog_name, prog_vers);
				exit(0);
			case 't':
				p.testing = 1;
				break;
			case 'h':
				print_usage("xtables-restore",
					    IPTABLES_VERSION);
				exit(0);
			case 'n':
				noflush = 1;
				break;
			case 'M':
				xtables_modprobe_program = optarg;
				break;
			case 'T':
				p.tablename = optarg;
				break;
			case '4':
				h.family = AF_INET;
				break;
			case '6':
				h.family = AF_INET6;
				xtables_set_nfproto(AF_INET6);
				break;
			case 'w': /* fallthrough.  Ignored by xt-restore */
			case 'W':
				break;
			default:
				fprintf(stderr,
					"Try `xtables-restore -h' for more information.\n");
				exit(1);
		}
	}

	if (optind == argc - 1) {
		p.in = fopen(argv[optind], "re");
		if (!p.in) {
			fprintf(stderr, "Can't open %s: %s\n", argv[optind],
				strerror(errno));
			exit(1);
		}
	} else if (optind < argc) {
		fprintf(stderr, "Unknown arguments found on commandline\n");
		exit(1);
	} else {
		p.in = stdin;
	}

	switch (family) {
	case NFPROTO_IPV4:
	case NFPROTO_IPV6: /* fallthough, same table */
		tables = xtables_ipv4;
#if defined(ALL_INCLUSIVE) || defined(NO_SHARED_LIBS)
		init_extensions();
		init_extensions4();
#endif
		break;
	case NFPROTO_ARP:
		tables = xtables_arp;
		break;
	case NFPROTO_BRIDGE:
		tables = xtables_bridge;
		break;
	default:
		fprintf(stderr, "Unknown family %d\n", family);
		return 1;
	}

	if (nft_init(&h, tables) < 0) {
		fprintf(stderr, "%s/%s Failed to initialize nft: %s\n",
				xtables_globals.program_name,
				xtables_globals.program_version,
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	xtables_restore_parse(&h, &p, &restore_cb, argc, argv);

	nft_fini(&h);
	fclose(p.in);
	return 0;
}

int xtables_ip4_restore_main(int argc, char *argv[])
{
	return xtables_restore_main(NFPROTO_IPV4, "iptables-restore",
				    argc, argv);
}

int xtables_ip6_restore_main(int argc, char *argv[])
{
	return xtables_restore_main(NFPROTO_IPV6, "ip6tables-restore",
				    argc, argv);
}

static const char *ebt_parse_table_name(const char *input)
{
	if (!strcmp(input, "broute"))
		xtables_error(PARAMETER_PROBLEM, "broute table not supported");
	else if (!strcmp(input, "filter"))
		return "filter";
	else if (!strcmp(input, "nat"))
		return "nat";

	xtables_error(PARAMETER_PROBLEM, "table '%s' not recognized", input);
}

static const char *ebt_parse_policy_name(const char *input)
{
	int i;

	for (i = 0; i < NUM_STANDARD_TARGETS; i++) {
		if (!strcmp(input, ebt_standard_targets[i])) {
			int policy = -i - 1;

			if (policy == EBT_CONTINUE)
				i = NUM_STANDARD_TARGETS;
			break;
		}
	}
	if (i == NUM_STANDARD_TARGETS)
		xtables_error(PARAMETER_PROBLEM, "invalid policy specified");
	return ebt_standard_targets[i];
}

static const struct option ebt_restore_options[] = {
	{.name = "noflush", .has_arg = 0, .val = 'n'},
	{ 0 }
};

int xtables_eb_restore_main(int argc, char *argv[])
{
	char buffer[10240];
	int i, ret, c, flush = 1;
	const char *table = NULL;
	struct nft_handle h;

	nft_init_eb(&h, "ebtables-restore");

	while ((c = getopt_long(argc, argv, "n",
				ebt_restore_options, NULL)) != -1) {
		switch(c) {
		case 'n':
			flush = 0;
			break;
		default:
			fprintf(stderr,
				"Usage: ebtables-restore [ --noflush ]\n");
			exit(1);
			break;
		}
	}

	while (fgets(buffer, sizeof(buffer), stdin)) {
		if (buffer[0] == '#' || buffer[0] == '\n')
			continue;
		if (buffer[0] == '*') {
			table = ebt_parse_table_name(buffer + 1);
			if (flush)
				nft_table_flush(&h, table);
			continue;
		} else if (!table) {
			xtables_error(PARAMETER_PROBLEM, "no table specified");
		}
		if (buffer[0] == ':') {
			char *ch, *chain = buffer;
			const char *policy;

			if (!(ch = strchr(buffer, ' ')))
				xtables_error(PARAMETER_PROBLEM, "no policy specified");
			*ch = '\0';
			policy = ebt_parse_policy_name(ch + 1);

			/* No need to check chain name for consistency, since
			 * we're supposed to be reading an automatically generated
			 * file. */
			if (ebt_get_current_chain(chain) < 0)
				nft_chain_user_add(&h, chain, table);
			ret = nft_chain_set(&h, table, chain, policy, NULL);
			if (ret < 0)
				xtables_error(PARAMETER_PROBLEM, "Wrong policy");
			continue;
		}

		newargc = 0;
		add_argv("ebtables", 0);
		add_argv("-t", 0);
		add_argv(table, 0);
		add_param_to_argv(buffer, line);

		DEBUGP("calling do_commandeb(%u, argv, &%s, handle):\n",
			newargc, table);

		for (i = 0; i < newargc; i++)
			DEBUGP("argv[%u]: %s\n", i, newargv[i]);

		optind = 0; /* Setting optind = 1 causes serious annoyances */
		if (!do_commandeb(&h, newargc, newargv, &newargv[2]))
			return 1;
	}

	if (!nft_commit(&h)) {
		fprintf(stderr, "%s\n", nft_strerror(errno));
		return 1;
	}
	return 0;
}
