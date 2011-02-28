INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(COVERAGE_LDFLAGS)

# build current directory before building gprs
SUBDIRS = . ipaccess gprs

# Conditional modules
if BUILD_NAT
SUBDIRS += nat
endif
if BUILD_BSC
SUBDIRS += bsc
endif

bin_PROGRAMS = bsc_hack bs11_config isdnsync bsc_mgcp
noinst_LIBRARIES = libbsc.a libmsc.a libvty.a libmgcp.a

libbsc_a_SOURCES = abis_rsl.c abis_nm.c abis_om2000.c gsm_data.c gsm_04_08_utils.c \
		chan_alloc.c debug.c socket.c abis_nm_vty.c abis_om2000_vty.c \
		gsm_subscriber_base.c subchan_demux.c bsc_rll.c transaction.c \
		trau_frame.c trau_mux.c paging.c \
		e1_config.c e1_input.c e1_input_vty.c \
		input/misdn.c input/ipaccess.c input/dahdi.c input/lapd.c \
		handover_logic.c talloc_ctx.c system_information.c rest_octets.c \
		bts_siemens_bs11.c bts_ipaccess_nanobts.c bts_ericsson_rbs2000.c mncc_upqueue.c \
		bts_unknown.c bsc_version.c bsc_api.c bsc_vty.c meas_rep.c gsm_04_80.c

libmsc_a_SOURCES = gsm_subscriber.c db.c \
		mncc.c mncc_builtin.c mncc_sock.c \
		gsm_04_08.c gsm_04_11.c transaction.c \
		token_auth.c rrlp.c ussd.c silent_call.c \
		handover_decision.c auth.c \
		osmo_msc.c rtp_proxy.c

libvty_a_SOURCES = common_vty.c

libmgcp_a_SOURCES = mgcp/mgcp_protocol.c mgcp/mgcp_network.c mgcp/mgcp_vty.c

bsc_hack_SOURCES = bsc_hack.c bsc_init.c bsc_vty.c vty_interface_layer3.c sms_queue.c
bsc_hack_LDADD = libmsc.a libbsc.a libvty.a libmsc.a \
		-ldl -ldbi $(LIBCRYPT) $(LIBOSMOVTY_LIBS)

bs11_config_SOURCES = bs11_config.c abis_nm.c gsm_data.c debug.c \
		      rs232.c bts_siemens_bs11.c

isdnsync_SOURCES = isdnsync.c

bsc_mgcp_SOURCES = mgcp/mgcp_main.c debug.c
bsc_mgcp_LDADD = libvty.a libmgcp.a $(LIBOSMOVTY_LIBS)

EXTRA_DIST = input/lapd.h
