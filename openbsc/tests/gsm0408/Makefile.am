AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOABIS_CFLAGS)
noinst_PROGRAMS = gsm0408_test

EXTRA_DIST = gsm0408_test.ok

gsm0408_test_SOURCES = gsm0408_test.c
gsm0408_test_LDADD =	$(top_builddir)/src/libbsc/libbsc.a \
			$(top_builddir)/src/libxsc/libxsc.a \
			$(top_builddir)/src/libtrau/libtrau.a \
			$(top_builddir)/src/libcommon/libcommon.a \
			$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOABIS_LIBS) -ldbi
