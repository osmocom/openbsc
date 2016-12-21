AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

OSMO_LIBS = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(NULL)

bin_PROGRAMS = \
	abisip-find \
	ipaccess-config \
	ipaccess-proxy \
	$(NULL)

abisip_find_LDADD = \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libtrau/libtrau.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(OSMO_LIBS) \
	$(NULL)

abisip_find_SOURCES = \
	abisip-find.c \
	$(NULL)

ipaccess_config_SOURCES = \
	ipaccess-config.c \
	ipaccess-firmware.c \
	network_listen.c \
	$(NULL)

# FIXME: resolve the bogus dependencies patched around here:
ipaccess_config_LDADD = \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libcommon-cs/libcommon-cs.a \
	$(top_builddir)/src/libtrau/libtrau.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(OSMO_LIBS) \
	$(NULL)

ipaccess_proxy_SOURCES = \
	ipaccess-proxy.c \
	$(NULL)

ipaccess_proxy_LDADD = \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libtrau/libtrau.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(OSMO_LIBS) \
	$(NULL)
