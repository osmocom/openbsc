INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMOSCCP_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS)

bin_PROGRAMS = osmo-bsc


osmo_bsc_SOURCES = osmo_bsc_main.c osmo_bsc_rf.c osmo_bsc_vty.c osmo_bsc_api.c \
		   osmo_bsc_grace.c osmo_bsc_msc.c \
		   $(top_srcdir)/src/debug.c $(top_srcdir)/src/bsc_msc.c \
		   $(top_srcdir)/src/bsc_init.c
osmo_bsc_LDADD = $(top_builddir)/src/libvty.a \
		 $(top_builddir)/src/libmgcp.a $(top_builddir)/src/libbsc.a \
		 $(LIBOSMOSCCP_LIBS)
