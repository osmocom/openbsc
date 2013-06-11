AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

EXTRA_DIST = mgcp_test.ok

noinst_PROGRAMS = mgcp_test

mgcp_test_SOURCES = mgcp_test.c

mgcp_test_LDADD = $(top_builddir)/src/libbsc/libbsc.a \
		$(top_builddir)/src/libmgcp/libmgcp.a \
		$(top_builddir)/src/libcommon/libcommon.a \
		$(LIBOSMOCORE_LIBS) -lrt $(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS)
