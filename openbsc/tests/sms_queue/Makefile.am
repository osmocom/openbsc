AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(NULL)

EXTRA_DIST = \
	sms_queue_test.ok \
	sms_queue_test.err \
	$(NULL)

noinst_PROGRAMS = \
	sms_queue_test \
	$(NULL)

sms_queue_test_SOURCES = \
	sms_queue_test.c \
	$(NULL)

sms_queue_test_LDADD = \
	$(top_builddir)/src/libmsc/libmsc.a \
	$(top_builddir)/src/libvlr/libvlr.a \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libtrau/libtrau.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(top_builddir)/src/libcommon-cs/libcommon-cs.a \
	$(LIBSMPP34_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBCRYPTO_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	-ldbi \
	-lrt \
	$(NULL)

sms_queue_test_LDFLAGS = \
	-Wl,--wrap=db_sms_get_next_unsent_rr_msisdn \
	$(NULL)
