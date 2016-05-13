AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMOSCCP_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

EXTRA_DIST = \
	bsc_nat_test.ok \
	bsc_data.c \
	barr.cfg \
	barr_dup.cfg \
	prefixes.csv \
	$(NULL)

noinst_PROGRAMS = \
	bsc_nat_test \
	$(NULL)

bsc_nat_test_SOURCES = \
	bsc_nat_test.c \
	$(top_srcdir)/src/osmo-bsc_nat/bsc_filter.c \
	$(top_srcdir)/src/osmo-bsc_nat/bsc_sccp.c \
	$(top_srcdir)/src/osmo-bsc_nat/bsc_nat_utils.c \
	$(top_srcdir)/src/osmo-bsc_nat/bsc_nat_rewrite.c \
	$(top_srcdir)/src/osmo-bsc_nat/bsc_nat_rewrite_trie.c \
	$(top_srcdir)/src/osmo-bsc_nat/bsc_mgcp_utils.c \
	$(top_srcdir)/src/osmo-bsc_nat/bsc_nat_filter.c

bsc_nat_test_LDADD = \
	$(top_builddir)/src/libfilter/libfilter.a \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libcommon-cs/libcommon-cs.a \
	$(top_builddir)/src/libmgcp/libmgcp.a \
	$(top_builddir)/src/libtrau/libtrau.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOSCCP_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	-lrt \
	$(NULL)
