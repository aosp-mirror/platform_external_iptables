/*
 * Shared library add-on to iptables to add quota support
 *
 * Sam Johnston <samj@samj.net>
 */
#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter/xt_quota.h>

enum {
	O_QUOTA = 0,
	O_REMAIN = 1,
};

static const struct xt_option_entry quota_opts[] = {
	{.name = "quota", .id = O_QUOTA, .type = XTTYPE_UINT64,
	 .flags = XTOPT_MAND | XTOPT_INVERT | XTOPT_PUT,
	 XTOPT_POINTER(struct xt_quota_info, quota)},
	{.name = "remain", .id = O_REMAIN, .type = XTTYPE_UINT64,
	 .flags = XTOPT_PUT, XTOPT_POINTER(struct xt_quota_info, remain)},
	XTOPT_TABLEEND,
};

static void quota_help(void)
{
	printf("quota match options:\n"
	       "[!] --quota quota		quota (bytes)\n"
	       "    --remain remain		remain (bytes)\n");
}

static void
quota_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_quota_info *q = (const void *)match->data;
	if (q->flags & XT_QUOTA_INVERT)
		printf(" !");
	printf(" quota: %llu bytes", (unsigned long long)q->quota);
	if (q->remain) {
		printf(" remain: %llu bytes",
			(unsigned long long)q->remain - 1);
	}
}

static void
quota_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_quota_info *q = (const void *)match->data;

	if (q->flags & XT_QUOTA_INVERT)
		printf(" !");
	printf(" --quota %llu", (unsigned long long) q->quota);
	if (q->remain) {
		printf(" --remain %llu",
			(unsigned long long) q->remain - 1);
	}
}

static void quota_parse(struct xt_option_call *cb)
{
	struct xt_quota_info *info = cb->data;

	xtables_option_parse(cb);
	if (cb->invert)
		info->flags |= XT_QUOTA_INVERT;
	if (cb->entry->id == O_REMAIN)
		info->remain++;
}

static int quota_xlate(struct xt_xlate *xl,
		       const struct xt_xlate_mt_params *params)
{
	const struct xt_quota_info *q = (void *)params->match->data;

	xt_xlate_add(xl, "quota %s%llu bytes",
		     q->flags & XT_QUOTA_INVERT ? "over " : "",
		     (unsigned long long) q->quota);
	return 1;
}

static struct xtables_match quota_match = {
	.family		= NFPROTO_UNSPEC,
	.name		= "quota",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof (struct xt_quota_info)),
	/*
	 * This size is only used for rule matching purpose when deleting
	 * rules. The real size copied out from new kernel xt_quota module
	 * is the whole struct xt_quota_info.
	 */
	.userspacesize	= offsetof(struct xt_quota_info, remain),
	.help		= quota_help,
	.print		= quota_print,
	.save		= quota_save,
	.x6_parse	= quota_parse,
	.x6_options	= quota_opts,
	.xlate		= quota_xlate,
};

void
_init(void)
{
	xtables_register_match(&quota_match);
}
