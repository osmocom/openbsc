AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOABIS_CFLAGS)
noinst_PROGRAMS = ss_test

# EXTRA_DIST = ss_test.ok

ss_test_SOURCES = ss_test.c
ss_test_LDADD =	$(top_builddir)/src/libbsc/libbsc.a \
			$(top_builddir)/src/libmsc/libmsc.a \
			$(top_builddir)/src/libbsc/libbsc.a \
			$(top_builddir)/src/libcommon/libcommon.a \
			$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) -ldbi
