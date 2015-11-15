INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

bin_PROGRAMS = osmo-mss

osmo_mss_SOURCES = mss_hack.c stubs.c
osmo_mss_LDADD = \
		$(top_builddir)/src/libmsc/libmsc.a \
		$(top_builddir)/src/libtrau/libtrau.a \
		$(top_builddir)/src/libcommon/libcommon.a \
		-ldbi -ldl $(LIBCRYPT) \
		$(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) $(LIBOSMOCORE_LIBS) \
		$(LIBOSMOCTRL_LIBS) $(LIBOSMOABIS_LIBS) $(LIBSMPP34_LIBS) $(LIBCRYPTO_LIBS)
