INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

bin_PROGRAMS = osmo-nitb

osmo_nitb_SOURCES = bsc_hack.c
osmo_nitb_LDADD = \
		$(top_builddir)/src/libbsc/libbsc.a \
		$(top_builddir)/src/libmsc/libmsc.a \
		$(top_builddir)/src/libbsc/libbsc.a \
		$(top_builddir)/src/libtrau/libtrau.a \
		$(top_builddir)/src/libabis/libabis.a \
		$(top_builddir)/src/libcommon/libcommon.a \
		$(top_builddir)/src/libctrl/libctrl.a \
		-ldbi -ldl $(LIBCRYPT) $(LIBOSMOGSM_LIBS) \
		$(LIBOSMOVTY_LIBS) $(LIBOSMOCORE_LIBS)
