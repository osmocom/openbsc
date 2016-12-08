AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBCARES_CFLAGS) \
	$(NULL)
if BUILD_IU
AM_CFLAGS += \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(NULL)
endif

EXTRA_DIST = \
	sgsn_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	sgsn_test \
	$(NULL)

sgsn_test_SOURCES = \
	sgsn_test.c \
	$(NULL)

sgsn_test_LDFLAGS = \
	-Wl,--wrap=RAND_bytes \
	-Wl,--wrap=sgsn_update_subscriber_data \
	-Wl,--wrap=gprs_subscr_request_update_location \
	-Wl,--wrap=gprs_subscr_request_auth_info \
	-Wl,--wrap=gsup_client_send \
	$(NULL)

sgsn_test_LDADD = \
	$(top_builddir)/src/gprs/gprs_llc_parse.o \
	$(top_builddir)/src/gprs/gprs_llc.o \
	$(top_builddir)/src/gprs/crc24.o \
	$(top_builddir)/src/gprs/gprs_sndcp.o \
	$(top_builddir)/src/gprs/gprs_gmm.o \
	$(top_builddir)/src/gprs/gprs_sgsn.o \
	$(top_builddir)/src/gprs/sgsn_vty.o \
	$(top_builddir)/src/gprs/sgsn_libgtp.o \
	$(top_builddir)/src/gprs/sgsn_auth.o \
	$(top_builddir)/src/gprs/sgsn_ares.o \
	$(top_builddir)/src/gprs/gprs_utils.o \
	$(top_builddir)/src/gprs/gprs_subscriber.o \
	$(top_builddir)/src/gprs/gprs_gb_parse.o \
        $(top_builddir)/src/gprs/gprs_llc_xid.o \
	$(top_builddir)/src/gprs/gprs_sndcp_xid.o \
        $(top_builddir)/src/gprs/slhc.o \
        $(top_builddir)/src/gprs/gprs_sndcp_comp.o \
        $(top_builddir)/src/gprs/gprs_sndcp_pcomp.o \
        $(top_builddir)/src/gprs/v42bis.o \
        $(top_builddir)/src/gprs/gprs_sndcp_dcomp.o \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOGB_LIBS) \
	$(LIBCARES_LIBS) \
	$(LIBCRYPTO_LIBS) \
	$(LIBGTP_LIBS) \
	-lrt \
	-lm \
	$(NULL)

if BUILD_IU
sgsn_test_LDADD += \
	$(top_builddir)/src/libiu/libiu.a \
	$(LIBOSMORANAP_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBASN1C_LIBS) \
	$(NULL)
endif
