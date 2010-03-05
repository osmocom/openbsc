INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS)

sbin_PROGRAMS = ipaccess-find ipaccess-config ipaccess-proxy

ipaccess_find_SOURCES = ipaccess-find.c

ipaccess_config_SOURCES = ipaccess-config.c ipaccess-firmware.c network_listen.c
ipaccess_config_LDADD = $(top_builddir)/src/libbsc.a $(top_builddir)/src/libmsc.a \
			$(top_builddir)/src/libbsc.a $(top_builddir)/src/libvty.a -ldl -ldbi $(LIBCRYPT)

ipaccess_proxy_SOURCES = ipaccess-proxy.c ../debug.c
