INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOABIS_CFLAGS)

EXTRA_DIST = handover_test.ok

noinst_PROGRAMS = handover_test

handover_test_SOURCES = handover_test.c
handover_test_LDADD = -ldl $(LIBOSMOCORE_LIBS) $(LIBOSMOABIS_LIBS) \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libmsc/libmsc.a -ldbi $(LIBOSMOGSM_LIBS)
