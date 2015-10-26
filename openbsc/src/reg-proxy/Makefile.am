AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall	$(COVERAGE_CFLAGS)			\
  	$(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOCTRL_CFLAGS) $(LIBOSMOABIS_CFLAGS) \
       -I/usr/include/sofia-sip-1.12

AM_LDFLAGS = $(COVERAGE_LDFLAGS)

bin_PROGRAMS = reg-proxy ussd-proxy

reg_proxy_SOURCES = \
		../gprs/gsm_04_08_gprs.c \
		../gprs/gprs_utils.c \
		../gprs/gprs_gsup_messages.c ../gprs/gprs_gsup_client.c \
		tcp_client.c sup_server.c sup.c sip.c sip_client.c reg_proxy.c

reg_proxy_LDADD = \
		-losipparser2 -losip2 \
		$(top_builddir)/src/libcommon/libcommon.a \
		-ldbi $(LIBCRYPT)				   \
		$(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) $(LIBOSMOCORE_LIBS)  \
		$(LIBOSMOCTRL_LIBS) $(LIBOSMOABIS_LIBS)


ussd_proxy_SOURCES = \
		ussd_proxy.c

ussd_proxy_LDADD = \
		-lsofia-sip-ua \
		$(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) $(LIBOSMOCORE_LIBS)  \
		$(LIBOSMOCTRL_LIBS) $(LIBOSMOABIS_LIBS)
