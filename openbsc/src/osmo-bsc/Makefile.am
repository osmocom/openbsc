INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS) $(COVERAGE_LDFLAGS)

bin_PROGRAMS = osmo-bsc


osmo_bsc_SOURCES = osmo_bsc_main.c osmo_bsc_rf.c osmo_bsc_vty.c osmo_bsc_api.c \
		   osmo_bsc_grace.c osmo_bsc_msc.c osmo_bsc_sccp.c \
		   osmo_bsc_filter.c osmo_bsc_bssap.c osmo_bsc_audio.c
# once again since TRAU uses CC symbol :(
osmo_bsc_LDADD = ../bsc/libbsc.a ../msc/libmsc.a ../bsc/libbsc.a \
		../abis/libabis.a ../trau/libtrau.a ../common/libcommon.a \
		 $(LIBOSMOSCCP_LIBS)
