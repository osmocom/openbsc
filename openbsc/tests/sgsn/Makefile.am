AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBCARES_CFLAGS)

EXTRA_DIST = sgsn_test.ok

noinst_PROGRAMS = sgsn_test

sgsn_test_SOURCES = sgsn_test.c
sgsn_test_LDFLAGS = \
	-Wl,--wrap=sgsn_update_subscriber_data \
	-Wl,--wrap=gprs_subscr_request_update_location \
	-Wl,--wrap=gprs_subscr_request_auth_info \
	-Wl,--wrap=gprs_gsup_client_send

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
	$(top_builddir)/src/gprs/gprs_gsup_messages.o \
	$(top_builddir)/src/gprs/gprs_gsup_client.o \
	$(top_builddir)/src/gprs/gprs_utils.o \
	$(top_builddir)/src/gprs/gprs_subscriber.o \
	$(top_builddir)/src/gprs/gsm_04_08_gprs.o \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOGB_LIBS) \
	$(LIBCARES_LIBS) \
	-lgtp -lrt

