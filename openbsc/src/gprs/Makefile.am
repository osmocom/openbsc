AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-fno-strict-aliasing \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOGB_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBCARES_CFLAGS) \
	$(LIBCRYPTO_CFLAGS) \
	$(LIBGTP_CFLAGS) \
	$(NULL)
if BUILD_IU
AM_CFLAGS += \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(NULL)
endif

OSMO_LIBS = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMOGB_LIBS) \
	$(LIBGTP_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(NULL)

bin_PROGRAMS = \
	osmo-gbproxy \
	$(NULL)
if HAVE_LIBGTP
if HAVE_LIBCARES
bin_PROGRAMS += \
	osmo-sgsn \
	osmo-gtphub \
	$(NULL)
endif
endif

osmo_gbproxy_SOURCES = \
	gb_proxy.c \
	gb_proxy_main.c \
	gb_proxy_vty.c \
	gb_proxy_patch.c \
	gb_proxy_tlli.c \
	gb_proxy_peer.c \
	gprs_gb_parse.c \
	gprs_llc_parse.c \
	crc24.c \
	gprs_utils.c \
	$(NULL)
osmo_gbproxy_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(OSMO_LIBS) \
	$(LIBCRYPTO_LIBS) \
	-lrt \
	$(NULL)

osmo_sgsn_SOURCES = \
	gprs_gmm.c \
	gprs_sgsn.c \
	gprs_sndcp.c \
	gprs_sndcp_comp.c \
	gprs_sndcp_dcomp.c \
	gprs_sndcp_pcomp.c \
	gprs_sndcp_vty.c \
	gprs_sndcp_xid.c \
	sgsn_main.c \
	sgsn_vty.c \
	sgsn_libgtp.c \
	gprs_llc.c \
	gprs_llc_parse.c \
	gprs_llc_vty.c \
	crc24.c \
	sgsn_ctrl.c \
	sgsn_auth.c \
	gprs_subscriber.c \
	gprs_utils.c \
	sgsn_cdr.c \
	sgsn_ares.c \
	slhc.c \
	gprs_llc_xid.c \
	v42bis.c \
	$(NULL)
osmo_sgsn_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(OSMO_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBCARES_LIBS) \
	$(LIBCRYPTO_LIBS) \
	$(LIBGTP_LIBS) \
	-lrt \
	-lm \
	$(NULL)
if BUILD_IU
osmo_sgsn_LDADD += \
	$(top_builddir)/src/libiu/libiu.a \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBOSMORANAP_LIBS) \
	$(LIBASN1C_LIBS) \
	$(NULL)
endif

osmo_gtphub_SOURCES = \
	gtphub_main.c \
	gtphub.c \
	gtphub_sock.c \
	gtphub_ares.c \
	gtphub_vty.c \
	sgsn_ares.c \
	gprs_utils.c \
	$(NULL)
osmo_gtphub_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBCARES_LIBS) \
	$(LIBGTP_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	-lrt \
	$(NULL)
