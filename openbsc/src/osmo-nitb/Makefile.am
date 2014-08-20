AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall	$(COVERAGE_CFLAGS)			\
  	$(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOCTRL_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(LIBSMPP34_CFLAGS)

AM_LDFLAGS = $(COVERAGE_LDFLAGS)

bin_PROGRAMS = osmo-nitb

osmo_nitb_SOURCES = bsc_hack.c
osmo_nitb_LDADD = \
		$(top_builddir)/src/libbsc/libbsc.a \
		$(top_builddir)/src/libmsc/libmsc.a \
		$(top_builddir)/src/libbsc/libbsc.a \
		$(top_builddir)/src/libtrau/libtrau.a \
		$(top_builddir)/src/libcommon/libcommon.a \
		-ldbi $(LIBCRYPT)				   \
		$(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) $(LIBOSMOCORE_LIBS)  \
		$(LIBOSMOCTRL_LIBS) $(LIBOSMOABIS_LIBS) $(LIBSMPP34_LIBS)
