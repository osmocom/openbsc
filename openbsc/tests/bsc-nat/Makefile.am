INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS)

EXTRA_DIST = bsc_data.c

noinst_PROGRAMS = bsc_nat_test

bsc_nat_test_SOURCES = bsc_nat_test.c \
			$(top_srcdir)/src/nat/bsc_filter.c \
			$(top_srcdir)/src/nat/bsc_sccp.c \
			$(top_srcdir)/src/nat/bsc_nat_utils.c \
			$(top_srcdir)/src/bssap.c
bsc_nat_test_LDADD = $(top_builddir)/src/libbsc.a $(top_builddir)/src/libsccp.a $(LIBOSMOCORE_LIBS)
