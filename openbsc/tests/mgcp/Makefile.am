INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

EXTRA_DIST = bsc_data.c

noinst_PROGRAMS = mgcp_test

mgcp_test_SOURCES = mgcp_test.c \
			$(top_srcdir)/src/mgcp/mgcp_protocol.c \
			$(top_srcdir)/src/mgcp/mgcp_network.c
mgcp_test_LDADD = $(top_builddir)/src/libbsc.a $(LIBOSMOCORE_LIBS) -lrt $(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS)
