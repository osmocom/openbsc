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
	$(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBOSMOSCCP_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

bin_PROGRAMS = \
	osmo-bsc \
	$(NULL)

osmo_bsc_SOURCES = \
	osmo_bsc_main.c \
	osmo_bsc_vty.c \
	osmo_bsc_api.c \
	osmo_bsc_grace.c \
	osmo_bsc_msc.c \
	osmo_bsc_sccp.c \
	osmo_bsc_filter.c \
	osmo_bsc_bssap.c \
	osmo_bsc_audio.c \
	osmo_bsc_ctrl.c \
	$(NULL)

# once again since TRAU uses CC symbol :(
osmo_bsc_LDADD = \
	$(top_builddir)/src/libfilter/libfilter.a \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libcommon-cs/libcommon-cs.a \
	$(top_builddir)/src/libmsc/libmsc.a \
	$(top_builddir)/src/libtrau/libtrau.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOSCCP_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(LIBOSMOABIS_LIBS) \
	$(NULL)
