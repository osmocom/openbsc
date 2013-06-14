AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

EXTRA_DIST = bsc_nat_trie_test.ok prefixes.csv

noinst_PROGRAMS = bsc_nat_trie_test

bsc_nat_trie_test_SOURCES = bsc_nat_trie_test.c \
			$(top_srcdir)/src/osmo-bsc_nat/bsc_nat_rewrite_trie.c
bsc_nat_trie_test_LDADD = $(top_builddir)/src/libbsc/libbsc.a \
			$(top_srcdir)/src/libctrl/libctrl.a \
			$(top_srcdir)/src/libmgcp/libmgcp.a \
			$(top_srcdir)/src/libtrau/libtrau.a \
			$(top_srcdir)/src/libcommon/libcommon.a \
			$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) -lrt \
			$(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS) \
			$(LIBOSMOABIS_LIBS)
