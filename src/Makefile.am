INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall

sbin_PROGRAMS = bsc_hack bs11_config ipaccess-find

bsc_hack_SOURCES = bsc_hack.c abis_rsl.c abis_nm.c gsm_04_08.c gsm_data.c \
		gsm_subscriber.c msgb.c select.c chan_alloc.c timer.c debug.c db.c \
		gsm_04_11.c telnet_interface.c telnet_parser.l subchan_demux.c \
		trau_frame.c trau_mux.c paging.c e1_config.c e1_input.c tlv_parser.c \
		input/misdn.c input/ipaccess.c signal.c gsm_utils.c
bsc_hack_LDADD = -ldl -ldbi

bs11_config_SOURCES = bs11_config.c abis_nm.c gsm_data.c msgb.c debug.c select.c timer.c rs232.c tlv_parser.c

ipaccess_find_SOURCES = ipaccess-find.c select.c timer.c
