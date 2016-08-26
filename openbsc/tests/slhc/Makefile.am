AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBCARES_CFLAGS)

EXTRA_DIST = slhc_test.ok

noinst_PROGRAMS = slhc_test

slhc_test_SOURCES = slhc_test.c

slhc_test_LDADD = \
	$(top_builddir)/src/gprs/slhc.o \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOCORE_LIBS)


