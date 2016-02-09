if BUILD_USSD_PROXY
AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall	$(COVERAGE_CFLAGS)			\
  	$(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOCTRL_CFLAGS) $(LIBOSMOABIS_CFLAGS) \
	   -I/usr/include/sofia-sip-1.12 -DNO_GSM0480_SEND_FUNC

AM_LDFLAGS = $(COVERAGE_LDFLAGS)

bin_PROGRAMS = ussd-proxy

ussd_proxy_SOURCES = \
		ussd_proxy.c ../libmsc/gsm_ussd_map_proto.c ../libmsc/gsm_04_80.c

ussd_proxy_LDADD = \
		-lsofia-sip-ua \
		$(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) $(LIBOSMOCORE_LIBS)  \
		$(LIBOSMOCTRL_LIBS) $(LIBOSMOABIS_LIBS)
endif
