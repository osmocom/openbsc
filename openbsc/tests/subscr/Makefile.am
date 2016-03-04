AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(LIBSMPP34_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

EXTRA_DIST = subscr_test.ok

noinst_PROGRAMS = subscr_test

subscr_test_SOURCES = subscr_test.c
subscr_test_LDADD   =	$(top_builddir)/src/libbsc/libbsc.a \
			$(top_builddir)/src/libxsc/libxsc.a \
			$(top_builddir)/src/libtrau/libtrau.a \
			$(top_builddir)/src/libcommon/libcommon.a \
			$(LIBOSMOCORE_LIBS) $(LIBOSMOABIS_LIBS) \
			$(LIBOSMOGSM_LIBS) $(LIBSMPP34_LIBS) $(LIBOSMOVTY_LIBS)
# -ldbi

