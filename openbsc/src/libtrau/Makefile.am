AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOABIS_LIBS) $(COVERAGE_LDFLAGS)

noinst_LIBRARIES = libtrau.a

libtrau_a_SOURCES = rtp_proxy.c trau_mux.c trau_upqueue.c

bin_PROGRAMS = osmo-rtpproxy

osmo_rtpproxy_SOURCES = rtp_proxy_main.c
osmo_rtpproxy_LDADD = libtrau.a ../libcommon/libcommon.a
osmo_rtpproxy_CFLAGS = $(AM_CFLAGS) $(LIBOSMOVTY_CFLAGS)
osmo_rtpproxy_LDFLAGS = $(AM_LDFLAGS) $(LIBOSMOVTY_LIBS)
