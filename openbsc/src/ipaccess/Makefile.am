AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS =  $(COVERAGE_LDFLAGS)
OSMO_LIBS = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOABIS_LIBS)

bin_PROGRAMS = ipaccess-find ipaccess-config ipaccess-proxy

ipaccess_find_LDADD = $(top_builddir)/src/libbsc/libbsc.a \
		      $(top_builddir)/src/libmsc/libmsc.a \
		      $(top_builddir)/src/libbsc/libbsc.a \
		      $(top_builddir)/src/libtrau/libtrau.a \
		      $(top_builddir)/src/libcommon/libcommon.a \
		      $(OSMO_LIBS)
ipaccess_find_SOURCES = ipaccess-find.c

ipaccess_config_SOURCES = ipaccess-config.c ipaccess-firmware.c network_listen.c

# FIXME: resolve the bogus dependencies patched around here:
ipaccess_config_LDADD = $(top_builddir)/src/libbsc/libbsc.a \
			$(top_builddir)/src/libmsc/libmsc.a \
			$(top_builddir)/src/libbsc/libbsc.a \
			$(top_builddir)/src/libtrau/libtrau.a \
			$(top_builddir)/src/libcommon/libcommon.a \
			-ldl -ldbi $(LIBCRYPT) $(OSMO_LIBS)

ipaccess_proxy_SOURCES = ipaccess-proxy.c
ipaccess_proxy_LDADD = $(top_builddir)/src/libbsc/libbsc.a \
		       $(top_builddir)/src/libmsc/libmsc.a \
		       $(top_builddir)/src/libbsc/libbsc.a \
		       $(top_builddir)/src/libtrau/libtrau.a \
		       $(top_builddir)/src/libcommon/libcommon.a \
		       $(OSMO_LIBS)
