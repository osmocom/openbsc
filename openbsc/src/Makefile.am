INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall

sbin_PROGRAMS = bsc_hack bs11_config ipaccess-find ipaccess-config isdnsync
noinst_LIBRARIES = libbsc.a libvty.a
noinst_HEADERS = vty/cardshell.h

libbsc_a_SOURCES = abis_rsl.c abis_nm.c gsm_04_08.c gsm_data.c mncc.c \
		gsm_subscriber.c msgb.c select.c chan_alloc.c timer.c debug.c db.c \
		gsm_04_11.c telnet_interface.c subchan_demux.c \
		trau_frame.c trau_mux.c paging.c e1_config.c e1_input.c tlv_parser.c \
		input/misdn.c input/ipaccess.c signal.c gsm_utils.c talloc.c

libvty_a_SOURCES = vty/buffer.c vty/command.c vty/vector.c vty/vty.c

bsc_hack_SOURCES = bsc_hack.c vty_interface.c
bsc_hack_LDADD = libbsc.a libvty.a -ldl -ldbi $(LIBCRYPT)

bs11_config_SOURCES = bs11_config.c abis_nm.c gsm_data.c msgb.c debug.c \
		      select.c timer.c rs232.c tlv_parser.c signal.c talloc.c

ipaccess_find_SOURCES = ipaccess-find.c select.c timer.c

ipaccess_config_SOURCES = ipaccess-config.c
ipaccess_config_LDADD = libbsc.a libvty.a -ldl -ldbi $(LIBCRYPT)

isdnsync_SOURCES = isdnsync.c
