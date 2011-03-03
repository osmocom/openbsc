INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS) $(COVERAGE_LDFLAGS)

bin_PROGRAMS = bsc_nat


bsc_nat_SOURCES = bsc_filter.c bsc_mgcp_utils.c bsc_nat.c bsc_nat_utils.c \
		  bsc_nat_vty.c bsc_sccp.c bsc_ussd.c
bsc_nat_LDADD = $(top_builddir)/src/common/libcommon.a \
		$(top_builddir)/src/mgcp/libmgcp.a $(top_builddir)/src/bsc/libbsc.a \
		$(top_builddir)/src/abis/libabis.a $(top_builddir)/src/trau/libtrau.a \
		-lrt $(LIBOSMOSCCP_LIBS)
