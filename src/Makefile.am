INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall

sbin_PROGRAMS = bsc_hack db_test

bsc_hack_SOURCES = bsc_hack.c misdn.c abis_rsl.c abis_nm.c gsm_04_08.c gsm_data.c \
		gsm_subscriber.c msgb.c select.c chan_alloc.c timer.c

db_test_SOURCES = db_test.c db.c
db_test_LDADD = -ldl -ldbi
