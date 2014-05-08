AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)

bin_PROGRAMS = osmo-bsc_mgcp

osmo_bsc_mgcp_SOURCES = mgcp_main.c

osmo_bsc_mgcp_LDADD = $(top_builddir)/src/libcommon/libcommon.a \
		 $(top_builddir)/src/libmgcp/libmgcp.a -lrt \
		 $(LIBOSMOVTY_LIBS) $(LIBOSMOCORE_LIBS) \
		 $(LIBOSMONETIF_LIBS) $(LIBBCG729_LIBS)
