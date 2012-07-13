INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

bin_PROGRAMS = osmo-ganc

osmo_ganc_SOURCES = conn.c ganc_server.c ganc_data.c ganc_vty.c main.c

osmo_ganc_LDADD = $(top_builddir)/src/libcommon/libcommon.a \
		  $(LIBOSMOSCCP_LIBS) $(LIBOSMOCORE_LIBS) \
		  $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) $(COVERAGE_LDFLAGS)
