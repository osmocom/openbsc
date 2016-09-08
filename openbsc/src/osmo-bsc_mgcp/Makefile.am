AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

bin_PROGRAMS = \
	osmo-bsc_mgcp \
	$(NULL)

osmo_bsc_mgcp_SOURCES = \
	mgcp_main.c \
	$(NULL)

osmo_bsc_mgcp_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(top_builddir)/src/libmgcp/libmgcp.a \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(LIBBCG729_LIBS) \
	$(LIBRARY_GSM) \
	-lrt \
	$(NULL)
