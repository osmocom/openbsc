AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)

noinst_LIBRARIES = libmsc.a

libmsc_a_SOURCES =	auth.c \
			db.c \
			gsm_04_08.c gsm_04_11.c gsm_04_80.c \
			gsm_subscriber.c \
			mncc.c mncc_builtin.c mncc_sock.c \
			rrlp.c \
			silent_call.c \
			sms_queue.c \
			token_auth.c \
			ussd.c \
			vty_interface_layer3.c \
			transaction.c \
			osmo_msc.c

if BUILD_SMPP
libmsc_a_SOURCES += smpp_smsc.c smpp_openbsc.c smpp_vty.c smpp_utils.c
endif
