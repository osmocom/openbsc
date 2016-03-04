AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOABIS_CFLAGS)

EXTRA_DIST = channel_test.ok

noinst_PROGRAMS = channel_test

channel_test_SOURCES = channel_test.c
channel_test_LDADD = \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libxsc/libxsc.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOCORE_LIBS) \
	-ldbi $(LIBOSMOGSM_LIBS) $(LIBCRYPTO_LIBS)
