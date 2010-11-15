INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

EXTRA_DIST = bsc_data.c

noinst_PROGRAMS = bsc_nat_test

bsc_nat_test_SOURCES = bsc_nat_test.c \
			$(top_srcdir)/src/common_vty.c \
			$(top_srcdir)/src/nat/bsc_filter.c \
			$(top_srcdir)/src/nat/bsc_sccp.c \
			$(top_srcdir)/src/nat/bsc_nat_utils.c \
			$(top_srcdir)/src/nat/bsc_mgcp_utils.c \
			$(top_srcdir)/src/mgcp/mgcp_protocol.c \
			$(top_srcdir)/src/mgcp/mgcp_network.c
bsc_nat_test_LDADD = $(top_builddir)/src/libbsc.a $(LIBOSMOCORE_LIBS) -lrt $(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS)
