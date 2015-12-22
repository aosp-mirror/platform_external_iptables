#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter/xt_cgroup.h>

enum {
	O_CLASSID = 0,
};

static void cgroup_help_v0(void)
{
	printf(
"cgroup match options:\n"
"[!] --cgroup classid            Match cgroup classid\n");
}

static const struct xt_option_entry cgroup_opts_v0[] = {
	{
		.name = "cgroup",
		.id = O_CLASSID,
		.type = XTTYPE_UINT32,
		.flags = XTOPT_INVERT | XTOPT_MAND | XTOPT_PUT,
		XTOPT_POINTER(struct xt_cgroup_info_v0, id)
	},
	XTOPT_TABLEEND,
};

static void cgroup_parse_v0(struct xt_option_call *cb)
{
	struct xt_cgroup_info_v0 *cgroupinfo = cb->data;

	xtables_option_parse(cb);
	if (cb->invert)
		cgroupinfo->invert = true;
}

static void
cgroup_print_v0(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_cgroup_info_v0 *info = (void *) match->data;

	printf(" cgroup %s%u", info->invert ? "! ":"", info->id);
}

static void cgroup_save_v0(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_cgroup_info_v0 *info = (void *) match->data;

	printf("%s --cgroup %u", info->invert ? " !" : "", info->id);
}

static struct xtables_match cgroup_match[] = {
	{
		.family		= NFPROTO_UNSPEC,
		.revision	= 0,
		.name		= "cgroup",
		.version	= XTABLES_VERSION,
		.size		= XT_ALIGN(sizeof(struct xt_cgroup_info_v0)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_cgroup_info_v0)),
		.help		= cgroup_help_v0,
		.print		= cgroup_print_v0,
		.save		= cgroup_save_v0,
		.x6_parse	= cgroup_parse_v0,
		.x6_options	= cgroup_opts_v0,
	},
};

void _init(void)
{
	xtables_register_matches(cgroup_match, ARRAY_SIZE(cgroup_match));
}
