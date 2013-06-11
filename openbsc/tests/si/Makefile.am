AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(COVERAGE_CFLAGS)

EXTRA_DIST = si_test.ok

noinst_PROGRAMS = si_test

si_test_SOURCES = si_test.c

si_test_LDADD = $(top_builddir)/src/libbsc/libbsc.a \
		$(top_builddir)/src/libcommon/libcommon.a \
		$(LIBOSMOCORE_LIBS) -lrt $(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS)
