INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

bin_PROGRAMS = osmo-bsc_nat


osmo_bsc_nat_SOURCES = bsc_filter.c bsc_mgcp_utils.c bsc_nat.c bsc_nat_utils.c \
		  bsc_nat_vty.c bsc_sccp.c bsc_ussd.c
osmo_bsc_nat_LDADD = $(top_builddir)/src/libcommon/libcommon.a \
		$(top_builddir)/src/libmgcp/libmgcp.a \
		$(top_builddir)/src/libbsc/libbsc.a \
		$(top_builddir)/src/libabis/libabis.a \
		$(top_builddir)/src/libtrau/libtrau.a \
		$(top_builddir)/src/libctrl/libctrl.a \
		-lrt $(LIBOSMOSCCP_LIBS) $(LIBOSMOCORE_LIBS) \
		$(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS)
