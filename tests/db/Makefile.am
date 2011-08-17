INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

noinst_PROGRAMS = db_test

db_test_SOURCES = db_test.c
db_test_LDADD =	$(top_builddir)/src/libbsc/libbsc.a \
		$(top_builddir)/src/libmsc/libmsc.a \
		$(top_builddir)/src/libbsc/libbsc.a \
		$(top_builddir)/src/libabis/libabis.a \
		$(top_builddir)/src/libtrau/libtrau.a \
		$(top_builddir)/src/libcommon/libcommon.a \
		$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) -ldl -ldbi

