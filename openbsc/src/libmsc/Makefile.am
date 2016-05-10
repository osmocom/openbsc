AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBCRYPTO_CFLAGS) \
	$(LIBSMPP34_CFLAGS) \
	$(NULL)

noinst_HEADERS = \
	meas_feed.h \
	$(NULL)

noinst_LIBRARIES = \
	libmsc.a \
	$(NULL)

libmsc_a_SOURCES = \
	auth.c \
	db.c \
	gsm_04_08.c \
	gsm_04_11.c \
	gsm_04_80.c \
	gsm_subscriber.c \
	mncc.c \
	mncc_builtin.c \
	mncc_sock.c \
	rrlp.c \
	silent_call.c \
	sms_queue.c \
	token_auth.c \
	ussd.c \
	vty_interface_layer3.c \
	transaction.c \
	osmo_msc.c \
	ctrl_commands.c \
	meas_feed.c \
	$(NULL)

if BUILD_SMPP
noinst_HEADERS += \
	smpp_smsc.h \
	$(NULL)

libmsc_a_SOURCES += \
	smpp_smsc.c \
	smpp_openbsc.c \
	smpp_vty.c \
	smpp_utils.c \
	$(NULL)
endif
