AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) $(COVERAGE_CFLAGS)

EXTRA_DIST = abis_test.ok

noinst_PROGRAMS = abis_test

abis_test_SOURCES = abis_test.c

abis_test_LDADD = \
		$(top_builddir)/src/libbsc/libbsc.a \
		$(top_builddir)/src/libcommon/libcommon.a \
		$(top_builddir)/src/libbsc/libbsc.a \
		$(top_builddir)/src/libtrau/libtrau.a \
		$(LIBOSMOCORE_LIBS) $(LIBOSMOABIS_LIBS) \
		$(LIBOSMOGSM_LIBS)
