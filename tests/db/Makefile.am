INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3

noinst_PROGRAMS = db_test

db_test_SOURCES = db_test.c $(top_srcdir)/src/db.c $(top_srcdir)/src/gsm_subscriber.c
db_test_LDADD = -ldl -ldbi

