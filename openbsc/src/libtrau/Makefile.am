AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOABIS_LIBS) $(COVERAGE_LDFLAGS)

noinst_LIBRARIES = libtrau.a

libtrau_a_SOURCES = rtp_proxy.c trau_mux.c trau_upqueue.c
