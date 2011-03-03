INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(COVERAGE_LDFLAGS)

bin_PROGRAMS = osmo-nitb

osmo_nitb_SOURCES = bsc_hack.c
osmo_nitb_LDADD = -ldl -ldbi $(LIBCRYPT) $(LIBOSMOVTY_LIBS) \
		../bsc/libbsc.a ../msc/libmsc.a ../bsc/libbsc.a ../trau/libtrau.a ../abis/libabis.a \
		../common/libcommon.a
