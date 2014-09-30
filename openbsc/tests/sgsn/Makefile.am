AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS)

EXTRA_DIST = sgsn_test.ok

noinst_PROGRAMS = sgsn_test

sgsn_test_SOURCES = sgsn_test.c
sgsn_test_LDADD = $(LIBOSMOCORE_LIBS)

