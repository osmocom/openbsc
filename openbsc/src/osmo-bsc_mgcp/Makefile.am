INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(COVERAGE_LDFLAGS)

bin_PROGRAMS = bsc_mgcp

bsc_mgcp_SOURCES = mgcp_main.c
bsc_mgcp_LDADD = $(top_srcdir)/src/common/libcommon.a $(top_srcdir)/src/mgcp/libmgcp.a \
		$(LIBOSMOVTY_LIBS)
