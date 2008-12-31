INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall

noinst_PROGRAMS = db_test

db_test_SOURCES = db_test.c $(top_srcdir)/src/db.c
db_test_LDADD = -ldl -ldbi

