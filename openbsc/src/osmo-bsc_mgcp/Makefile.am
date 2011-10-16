INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

bin_PROGRAMS = bsc_mgcp

bsc_mgcp_SOURCES = mgcp_main.c
bsc_mgcp_LDADD = $(top_builddir)/src/libcommon/libcommon.a \
		 $(top_builddir)/src/libmgcp/libmgcp.a \
		 $(LIBOSMOVTY_LIBS) $(LIBOSMOCORE_LIBS)
