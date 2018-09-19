# -*- Makefile -*-

AM_CFLAGS        = ${regular_CFLAGS}
AM_CPPFLAGS      = ${regular_CPPFLAGS} -I${top_builddir}/include -I${top_srcdir}/include -I${top_srcdir} ${kinclude_CPPFLAGS} ${libmnl_CFLAGS} ${libnftnl_CFLAGS} ${libnetfilter_conntrack_CFLAGS}
AM_YFLAGS = -d

BUILT_SOURCES =

xtables_legacy_multi_SOURCES  = xtables-legacy-multi.c iptables-xml.c
xtables_legacy_multi_CFLAGS   = ${AM_CFLAGS}
xtables_legacy_multi_LDADD    = ../extensions/libext.a
if ENABLE_STATIC
xtables_legacy_multi_CFLAGS  += -DALL_INCLUSIVE
endif
if ENABLE_IPV4
xtables_legacy_multi_SOURCES += iptables-save.c iptables-restore.c \
                         iptables-standalone.c iptables.c
xtables_legacy_multi_CFLAGS  += -DENABLE_IPV4
xtables_legacy_multi_LDADD   += ../libiptc/libip4tc.la ../extensions/libext4.a
endif
if ENABLE_IPV6
xtables_legacy_multi_SOURCES += ip6tables-save.c ip6tables-restore.c \
                          ip6tables-standalone.c ip6tables.c
xtables_legacy_multi_CFLAGS  += -DENABLE_IPV6
xtables_legacy_multi_LDADD   += ../libiptc/libip6tc.la ../extensions/libext6.a
endif
xtables_legacy_multi_SOURCES += xshared.c
xtables_legacy_multi_LDADD   += ../libxtables/libxtables.la -lm

# iptables using nf_tables api
if ENABLE_NFTABLES
BUILT_SOURCES += xtables-config-parser.h
xtables_nft_multi_SOURCES  = xtables-nft-multi.c iptables-xml.c
xtables_nft_multi_CFLAGS   = ${AM_CFLAGS}
xtables_nft_multi_LDADD    = ../extensions/libext.a ../extensions/libext_ebt.a
if ENABLE_STATIC
xtables_nft_multi_CFLAGS  += -DALL_INCLUSIVE
endif
xtables_nft_multi_CFLAGS  += -DENABLE_NFTABLES -DENABLE_IPV4 -DENABLE_IPV6
xtables_nft_multi_SOURCES += xtables-config-parser.y xtables-config-syntax.l
xtables_nft_multi_SOURCES += xtables-save.c xtables-restore.c \
				xtables-standalone.c xtables.c nft.c \
				nft-shared.c nft-ipv4.c nft-ipv6.c nft-arp.c \
				xtables-monitor.c \
				xtables-arp-standalone.c xtables-arp.c \
				nft-bridge.c \
				xtables-eb-standalone.c xtables-eb.c \
				xtables-eb-translate.c \
				xtables-translate.c
xtables_nft_multi_LDADD   += ${libmnl_LIBS} ${libnftnl_LIBS} ${libnetfilter_conntrack_LIBS} ../extensions/libext4.a ../extensions/libext6.a ../extensions/libext_ebt.a ../extensions/libext_arpt.a
# yacc and lex generate dirty code
xtables_nft_multi-xtables-config-parser.o xtables_nft_multi-xtables-config-syntax.o: AM_CFLAGS += -Wno-missing-prototypes -Wno-missing-declarations -Wno-implicit-function-declaration -Wno-nested-externs -Wno-undef -Wno-redundant-decls
xtables_nft_multi_SOURCES += xshared.c
xtables_nft_multi_LDADD   += ../libxtables/libxtables.la -lm
endif

sbin_PROGRAMS    = xtables-legacy-multi
if ENABLE_NFTABLES
sbin_PROGRAMS	+= xtables-nft-multi
endif
man_MANS         = iptables.8 iptables-restore.8 iptables-save.8 \
                   iptables-xml.1 ip6tables.8 ip6tables-restore.8 \
                   ip6tables-save.8 iptables-extensions.8 \
                   xtables-nft.8 xtables-translate.8 xtables-legacy.8 \
                   xtables-monitor.8
CLEANFILES       = iptables.8 xtables-monitor.8 \
		   xtables-config-parser.c xtables-config-syntax.c

vx_bin_links   = iptables-xml
if ENABLE_IPV4
v4_sbin_links  = iptables-legacy iptables-legacy-restore iptables-legacy-save \
		 iptables iptables-restore iptables-save
endif
if ENABLE_IPV6
v6_sbin_links  = ip6tables-legacy ip6tables-legacy-restore ip6tables-legacy-save \
		 ip6tables ip6tables-restore ip6tables-save
endif
if ENABLE_NFTABLES
x_sbin_links  = iptables-nft iptables-nft-restore iptables-nft-save \
		ip6tables-nft ip6tables-nft-restore ip6tables-nft-save \
		iptables-translate ip6tables-translate \
		iptables-restore-translate ip6tables-restore-translate \
		arptables-nft arptables \
		arptables-nft-restore arptables-restore \
		arptables-nft-save arptables-save \
		ebtables-nft ebtables \
		ebtables-nft-restore ebtables-restore \
		ebtables-nft-save ebtables-save \
		xtables-monitor
endif

iptables-extensions.8: iptables-extensions.8.tmpl ../extensions/matches.man ../extensions/targets.man
	${AM_VERBOSE_GEN} sed \
		-e '/@MATCH@/ r ../extensions/matches.man' \
		-e '/@TARGET@/ r ../extensions/targets.man' $< >$@;

pkgconfig_DATA = xtables.pc

# Using if..fi avoids an ugly "error (ignored)" message :)
install-exec-hook:
	-if test -z "${DESTDIR}"; then /sbin/ldconfig; fi;
	${INSTALL} -dm0755 "${DESTDIR}${bindir}";
	for i in ${vx_bin_links}; do ${LN_S} -f "${sbindir}/xtables-legacy-multi" "${DESTDIR}${bindir}/$$i"; done;
	for i in ${v4_sbin_links}; do ${LN_S} -f xtables-legacy-multi "${DESTDIR}${sbindir}/$$i"; done;
	for i in ${v6_sbin_links}; do ${LN_S} -f xtables-legacy-multi "${DESTDIR}${sbindir}/$$i"; done;
	for i in ${x_sbin_links}; do ${LN_S} -f xtables-nft-multi "${DESTDIR}${sbindir}/$$i"; done;
