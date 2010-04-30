INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS)

sbin_PROGRAMS = bsc_hack bs11_config ipaccess-find ipaccess-config \
                isdnsync bsc_mgcp ipaccess-proxy osmo-gb_proxy
noinst_LIBRARIES = libbsc.a libmsc.a libvty.a libsccp.a libsgsn.a
noinst_HEADERS = vty/cardshell.h

bscdir = $(libdir)
bsc_LIBRARIES = libsccp.a

libbsc_a_SOURCES = abis_rsl.c abis_nm.c gsm_data.c gsm_04_08_utils.c \
		chan_alloc.c debug.c socket.c \
		gsm_subscriber_base.c subchan_demux.c bsc_rll.c transaction.c \
		trau_frame.c trau_mux.c paging.c e1_config.c e1_input.c \
		input/misdn.c input/ipaccess.c \
		talloc_ctx.c system_information.c rest_octets.c \
		rtp_proxy.c bts_siemens_bs11.c bts_ipaccess_nanobts.c \
		bts_unknown.c bsc_version.c bsc_api.c

libsgsn_a_SOURCES = gprs_ns.c gprs_bssgp.c gprs_llc.c gsm_04_08_gprs.c \
		crc24.c gprs_sgsn.c

libmsc_a_SOURCES = gsm_subscriber.c db.c \
		mncc.c gsm_04_08.c gsm_04_11.c transaction.c \
		token_auth.c rrlp.c gsm_04_80.c ussd.c silent_call.c \
		handover_logic.c handover_decision.c meas_rep.c

libvty_a_SOURCES = vty/buffer.c vty/command.c vty/vector.c vty/vty.c \
		telnet_interface.c vty_interface_cmds.c

libsccp_a_SOURCES = sccp/sccp.c

bsc_hack_SOURCES = bsc_hack.c bsc_init.c vty_interface.c vty_interface_layer3.c
bsc_hack_LDADD = libmsc.a libbsc.a libmsc.a libsgsn.a libvty.a -ldl -ldbi $(LIBCRYPT)

bs11_config_SOURCES = bs11_config.c abis_nm.c gsm_data.c debug.c \
		      rs232.c bts_siemens_bs11.c

ipaccess_find_SOURCES = ipaccess/ipaccess-find.c

ipaccess_config_SOURCES = ipaccess/ipaccess-config.c ipaccess/ipaccess-firmware.c
ipaccess_config_LDADD = libbsc.a libmsc.a libbsc.a libvty.a -ldl -ldbi $(LIBCRYPT)

isdnsync_SOURCES = isdnsync.c

bsc_mgcp_SOURCES = mgcp/mgcp_main.c mgcp/mgcp_protocol.c mgcp/mgcp_network.c mgcp/mgcp_vty.c \
		   debug.c
bsc_mgcp_LDADD = libvty.a

ipaccess_proxy_SOURCES = ipaccess/ipaccess-proxy.c debug.c

osmo_gb_proxy_SOURCES = gb_proxy.c gb_proxy_main.c \
			gprs_ns.c \
			socket.c debug.c telnet_interface.c vty_interface_cmds.c 
osmo_gb_proxy_LDADD = libvty.a
