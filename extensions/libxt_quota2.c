/*
 *	"quota2" match extension for iptables
 *	Sam Johnston <samj [at] samj net>
 *	Jan Engelhardt <jengelh [at] medozas de>, 2008
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtables.h>
#include "xt_quota2.h"
#include "compat_user.h"

enum {
	FL_QUOTA     = 1 << 0,
	FL_NAME      = 1 << 1,
	FL_GROW      = 1 << 2,
	FL_PACKET    = 1 << 3,
	FL_NO_CHANGE = 1 << 4,
};

static const struct option quota_mt2_opts[] = {
	{.name = "grow",      .has_arg = false, .val = 'g'},
	{.name = "no-change", .has_arg = false, .val = 'c'},
	{.name = "name",      .has_arg = true,  .val = 'n'},
	{.name = "quota",     .has_arg = true,  .val = 'q'},
	{.name = "packets",   .has_arg = false, .val = 'p'},
	{NULL},
};

static void quota_mt2_help(void)
{
	printf(
	"quota match options:\n"
	"    --grow           provide an increasing counter\n"
	"    --no-change      never change counter/quota value for matching packets\n"
	"    --name name      name for the file in sysfs\n"
	"[!] --quota quota    initial quota (bytes or packets)\n"
	"    --packets        count packets instead of bytes\n"
	);
}

static int
quota_mt2_parse(int c, char **argv, int invert, unsigned int *flags,
	        const void *entry, struct xt_entry_match **match)
{
	struct xt_quota_mtinfo2 *info = (void *)(*match)->data;
	char *end;

	switch (c) {
	case 'g':
		xtables_param_act(XTF_ONLY_ONCE, "quota", "--grow", *flags & FL_GROW);
		xtables_param_act(XTF_NO_INVERT, "quota", "--grow", invert);
		info->flags |= XT_QUOTA_GROW;
		*flags |= FL_GROW;
		return true;
	case 'c': /* no-change */
		xtables_param_act(XTF_ONLY_ONCE, "quota", "--no-change", *flags & FL_NO_CHANGE);
		xtables_param_act(XTF_NO_INVERT, "quota", "--no-change", invert);
		info->flags |= XT_QUOTA_NO_CHANGE;
		*flags |= FL_NO_CHANGE;
		return true;
	case 'n':
		/* zero termination done on behalf of the kernel module */
		xtables_param_act(XTF_ONLY_ONCE, "quota", "--name", *flags & FL_NAME);
		xtables_param_act(XTF_NO_INVERT, "quota", "--name", invert);
		strncpy(info->name, optarg, sizeof(info->name));
		*flags |= FL_NAME;
		return true;
	case 'p':
		xtables_param_act(XTF_ONLY_ONCE, "quota", "--packets", *flags & FL_PACKET);
		xtables_param_act(XTF_NO_INVERT, "quota", "--packets", invert);
		info->flags |= XT_QUOTA_PACKET;
		*flags |= FL_PACKET;
		return true;
	case 'q':
		xtables_param_act(XTF_ONLY_ONCE, "quota", "--quota", *flags & FL_QUOTA);
		if (invert)
			info->flags |= XT_QUOTA_INVERT;
		info->quota = strtoull(optarg, &end, 0);
		if (*end != '\0')
			xtables_error(PARAMETER_PROBLEM, "quota match: "
			           "invalid value for --quota");
		*flags |= FL_QUOTA;
		return true;
	}
	return false;
}

static void
quota_mt2_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_quota_mtinfo2 *q = (void *)match->data;

	if (q->flags & XT_QUOTA_INVERT)
		printf(" !");
	if (q->flags & XT_QUOTA_GROW)
		printf(" --grow ");
	if (q->flags & XT_QUOTA_NO_CHANGE)
		printf(" --no-change ");
	if (q->flags & XT_QUOTA_PACKET)
		printf(" --packets ");
	if (*q->name != '\0')
		printf(" --name %s ", q->name);
	printf(" --quota %llu ", (unsigned long long)q->quota);
}

static void quota_mt2_print(const void *ip, const struct xt_entry_match *match,
                            int numeric)
{
	const struct xt_quota_mtinfo2 *q = (const void *)match->data;

	if (q->flags & XT_QUOTA_INVERT)
		printf(" !");
	if (q->flags & XT_QUOTA_GROW)
		printf(" counter");
	else
		printf(" quota");
	if (*q->name != '\0')
		printf(" %s:", q->name);
	printf(" %llu ", (unsigned long long)q->quota);
	if (q->flags & XT_QUOTA_PACKET)
		printf("packets ");
	else
		printf("bytes ");
	if (q->flags & XT_QUOTA_NO_CHANGE)
		printf("(no-change mode) ");
}

static struct xtables_match quota_mt2_reg = {
	.family        = NFPROTO_UNSPEC,
	.revision      = 3,
	.name          = "quota2",
	.version       = XTABLES_VERSION,
	.size          = XT_ALIGN(sizeof (struct xt_quota_mtinfo2)),
	.userspacesize = offsetof(struct xt_quota_mtinfo2, quota),
	.help          = quota_mt2_help,
	.parse         = quota_mt2_parse,
	.print         = quota_mt2_print,
	.save          = quota_mt2_save,
	.extra_opts    = quota_mt2_opts,
};

static __attribute__((constructor)) void quota2_mt_ldr(void)
{
	xtables_register_match(&quota_mt2_reg);
}
