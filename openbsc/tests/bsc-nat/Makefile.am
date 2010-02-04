INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3

noinst_PROGRAMS = bsc_nat_test

bsc_nat_test_SOURCES = bsc_nat_test.c $(top_srcdir)/src/nat/bsc_filter.c
bsc_nat_test_LDADD = $(top_builddir)/src/libbsc.a $(top_builddir)/src/libsccp.a
