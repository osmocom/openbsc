INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(COVERAGE_LDFLAGS)

noinst_LIBRARIES = libtrau.a

libtrau_a_SOURCES = rtp_proxy.c subchan_demux.c trau_frame.c trau_mux.c trau_upqueue.c
