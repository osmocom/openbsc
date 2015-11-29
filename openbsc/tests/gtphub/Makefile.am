AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS)

EXTRA_DIST = \
	gtphub_test.ok

if HAVE_LIBGTP
if HAVE_LIBCARES
noinst_PROGRAMS = gtphub_test
endif
endif

gtphub_test_SOURCES = gtphub_test.c
gtphub_test_LDFLAGS = \
	-Wl,--wrap=gtphub_resolve_ggsn_addr \
	-Wl,--wrap=gtphub_ares_init

gtphub_test_LDADD = \
	$(top_builddir)/src/gprs/gtphub.o \
	$(top_builddir)/src/gprs/gprs_utils.o \
	$(LIBOSMOCORE_LIBS) \
	-lgtp -lrt

