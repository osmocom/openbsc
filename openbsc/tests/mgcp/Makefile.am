AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_srcdir)
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(COVERAGE_CFLAGS) $(LIBBCG729_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

EXTRA_DIST = mgcp_test.ok mgcp_transcoding_test.ok

noinst_PROGRAMS = mgcp_test

if BUILD_MGCP_TRANSCODING
noinst_PROGRAMS += mgcp_transcoding_test
endif

mgcp_test_SOURCES = mgcp_test.c

mgcp_test_LDADD = $(top_builddir)/src/libbsc/libbsc.a \
		$(top_builddir)/src/libmgcp/libmgcp.a \
		$(top_builddir)/src/libcommon/libcommon.a \
		$(LIBOSMOCORE_LIBS) -lrt -lm $(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS) \
		$(LIBRARY_DL) $(LIBOSMONETIF_LIBS)

mgcp_transcoding_test_SOURCES = mgcp_transcoding_test.c

mgcp_transcoding_test_LDADD = \
		$(top_builddir)/src/libbsc/libbsc.a \
		$(top_builddir)/src/libmgcp/libmgcp.a \
		$(top_builddir)/src/libcommon/libcommon.a \
		$(LIBOSMOCORE_LIBS) $(LIBBCG729_LIBS) -lrt -lm $(LIBOSMOSCCP_LIBS) $(LIBOSMOVTY_LIBS) \
		$(LIBRARY_DL) $(LIBOSMONETIF_LIBS)
