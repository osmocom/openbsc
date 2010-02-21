INCLUDES = $(all_includes) -I$(top_srcdir)/include
noinst_PROGRAMS = gsm0408_test

gsm0408_test_SOURCES = gsm0408_test.c
gsm0408_test_LDADD = $(top_builddir)/src/libbsc.a $(top_builddir)/src/libmsc.a $(top_builddir)/src/libbsc.a $(LIBOSMOCORE_LIBS) -ldbi
