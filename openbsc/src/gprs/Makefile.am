AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall -fno-strict-aliasing $(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) $(LIBOSMOGB_CFLAGS) $(COVERAGE_CFLAGS) \
	$(LIBCARES_CFLAGS) $(LIBCRYPTO_CFLAGS)
OSMO_LIBS = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) \
	    $(LIBOSMOCTRL_LIBS) $(LIBOSMOGB_LIBS)

noinst_HEADERS = gprs_sndcp.h

bin_PROGRAMS = osmo-gbproxy

if HAVE_LIBGTP
if HAVE_LIBCARES
bin_PROGRAMS += osmo-sgsn osmo-gtphub
endif
endif

osmo_gbproxy_SOURCES =  gb_proxy.c gb_proxy_main.c gb_proxy_vty.c \
			gb_proxy_patch.c gb_proxy_tlli.c gb_proxy_peer.c \
			gprs_gb_parse.c gprs_llc_parse.c crc24.c gprs_utils.c
osmo_gbproxy_LDADD = 	$(top_builddir)/src/libcommon/libcommon.a \
			$(OSMO_LIBS) $(LIBCRYPTO_LIBS) -lrt

osmo_sgsn_SOURCES =	gprs_gmm.c gprs_sgsn.c gprs_sndcp.c gprs_sndcp_vty.c \
			sgsn_main.c sgsn_vty.c sgsn_libgtp.c \
			gprs_llc.c gprs_llc_parse.c gprs_llc_vty.c crc24.c \
			sgsn_ctrl.c sgsn_auth.c gprs_subscriber.c \
			gprs_gsup_messages.c gprs_utils.c gprs_gsup_client.c \
			gsm_04_08_gprs.c sgsn_cdr.c sgsn_ares.c \
			oap.c oap_messages.c
osmo_sgsn_LDADD = 	\
			$(top_builddir)/src/libcommon/libcommon.a \
			-lgtp $(OSMO_LIBS) $(LIBOSMOABIS_LIBS) $(LIBCARES_LIBS) \
			$(LIBCRYPTO_LIBS) -lrt

osmo_gtphub_SOURCES =	gtphub_main.c gtphub.c gtphub_ares.c gtphub_vty.c \
			sgsn_ares.c gprs_utils.c
osmo_gtphub_LDADD = 	\
			$(top_builddir)/src/libcommon/libcommon.a \
			-lgtp $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) \
			$(LIBCARES_LIBS) -lrt
