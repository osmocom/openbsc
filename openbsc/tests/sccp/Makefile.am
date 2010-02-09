INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3

noinst_PROGRAMS = sccp_test

sccp_test_SOURCES = sccp_test.c
sccp_test_LDADD = $(top_builddir)/src/libsccp.a $(top_builddir)/src/libbsc.a $(top_builddir)/src/liblaf0rge1.a

