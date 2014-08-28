AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS = -Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
	    $(LIBOSMONETIF_CFLAGS) $(COVERAGE_CFLAGS) $(LIBBCG729_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) \
	     $(LIBOSMONETIF_LIBS) $(COVERAGE_LDFLAGS) $(LIBBCG729_LIBS)

noinst_LIBRARIES = libmgcp.a

noinst_HEADERS = g711common.h

libmgcp_a_SOURCES = mgcp_protocol.c mgcp_network.c mgcp_vty.c mgcp_osmux.c

if BUILD_MGCP_TRANSCODING
    libmgcp_a_SOURCES += mgcp_transcode.c
endif
