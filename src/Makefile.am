INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall

sbin_PROGRAMS = bsc_hack

bsc_hack_SOURCES = bsc_hack.c misdn.c abis_rsl.c abis_nm.c gsm_04_08.c gsm_data.c \
		gsm_subscriber.c msgb.c select.c chan_alloc.c timer.c debug.c db.c \
		gsm_04_11.c telnet_interface.c telnet_parser.l
bsc_hack_LDADD = -ldl -ldbi
