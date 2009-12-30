INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall

sbin_PROGRAMS = bsc_hack bs11_config ipaccess-find ipaccess-config \
                isdnsync bsc_mgcp ipaccess-firmware ipaccess-proxy
noinst_LIBRARIES = libbsc.a libmsc.a libvty.a libsccp.a
noinst_HEADERS = vty/cardshell.h

libbsc_a_SOURCES = abis_rsl.c abis_nm.c gsm_data.c gsm_04_08_utils.c \
		msgb.c select.c chan_alloc.c timer.c debug.c \
		gsm_subscriber_base.c subchan_demux.c bsc_rll.c transaction.c \
		trau_frame.c trau_mux.c paging.c e1_config.c e1_input.c tlv_parser.c \
		input/misdn.c input/ipaccess.c signal.c gsm_utils.c talloc.c \
		talloc_ctx.c system_information.c bitvec.c rest_octets.c \
		rtp_proxy.c statistics.c

libmsc_a_SOURCES = gsm_subscriber.c db.c telnet_interface.c \
		mncc.c gsm_04_08.c gsm_04_11.c transaction.c \
		token_auth.c rrlp.c gsm_04_80.c ussd.c silent_call.c \
		handover_logic.c handover_decision.c meas_rep.c

libvty_a_SOURCES = vty/buffer.c vty/command.c vty/vector.c vty/vty.c

libsccp_a_SOURCES = sccp/sccp.c

bsc_hack_SOURCES = bsc_hack.c bsc_init.c vty_interface.c vty_interface_layer3.c
bsc_hack_LDADD = libmsc.a libbsc.a libmsc.a libvty.a -ldl -ldbi $(LIBCRYPT)

bs11_config_SOURCES = bs11_config.c abis_nm.c gsm_data.c msgb.c debug.c \
		      select.c timer.c rs232.c tlv_parser.c signal.c talloc.c

ipaccess_find_SOURCES = ipaccess/ipaccess-find.c select.c timer.c

ipaccess_config_SOURCES = ipaccess/ipaccess-config.c
ipaccess_config_LDADD = libbsc.a libmsc.a libbsc.a libvty.a -ldl -ldbi $(LIBCRYPT)

isdnsync_SOURCES = isdnsync.c

bsc_mgcp_SOURCES = bsc_mgcp.c msgb.c talloc.c debug.c select.c timer.c telnet_interface.c
bsc_mgcp_LDADD = libvty.a

ipaccess_firmware_SOURCES = ipaccess/ipaccess-firmware.c talloc.c

ipaccess_proxy_SOURCES = ipaccess/ipaccess-proxy.c msgb.c select.c talloc.c debug.c timer.c
