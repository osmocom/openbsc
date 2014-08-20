AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOCTRL_LIBS) $(LIBOSMOSCCP_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(LIBOSMONETIF_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

EXTRA_DIST = bsc_nat_test.ok bsc_data.c barr.cfg barr_dup.cfg prefixes.csv

noinst_PROGRAMS = bsc_nat_test

bsc_nat_test_SOURCES = bsc_nat_test.c \
			$(top_srcdir)/src/osmo-bsc_nat/bsc_filter.c \
			$(top_srcdir)/src/osmo-bsc_nat/bsc_sccp.c \
			$(top_srcdir)/src/osmo-bsc_nat/bsc_nat_utils.c \
			$(top_srcdir)/src/osmo-bsc_nat/bsc_nat_filter.c \
			$(top_srcdir)/src/osmo-bsc_nat/bsc_nat_rewrite.c \
			$(top_srcdir)/src/osmo-bsc_nat/bsc_nat_rewrite_trie.c \
			$(top_srcdir)/src/osmo-bsc_nat/bsc_mgcp_utils.c
bsc_nat_test_LDADD = $(top_builddir)/src/libbsc/libbsc.a \
			$(top_builddir)/src/libmgcp/libmgcp.a \
			$(top_builddir)/src/libtrau/libtrau.a \
			$(top_builddir)/src/libcommon/libcommon.a \
			$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) -lrt \
			$(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS) \
			$(LIBOSMOABIS_LIBS) $(LIBOSMONETIF_LIBS) \
			$(LIBOSMOCTRL_LIBS)
