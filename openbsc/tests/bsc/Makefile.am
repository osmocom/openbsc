AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

EXTRA_DIST = bsc_test.ok

noinst_PROGRAMS = bsc_test

bsc_test_SOURCES = bsc_test.c \
			$(top_srcdir)/src/osmo-bsc/osmo_bsc_filter.c
bsc_test_LDADD = $(top_builddir)/src/libbsc/libbsc.a \
			$(top_builddir)/src/libmsc/libmsc.a \
			$(top_builddir)/src/libmgcp/libmgcp.a \
			$(top_builddir)/src/libtrau/libtrau.a \
			$(top_builddir)/src/libcommon/libcommon.a \
			$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) -lrt \
			$(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS) \
			$(LIBOSMOABIS_LIBS)
