INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS)

if HAVE_LIBGTP
sbin_PROGRAMS = osmo-gbproxy osmo-sgsn
noinst_LIBRARIES = libsgsn.a
else
sbin_PROGRAMS = osmo-gbproxy
endif


libsgsn_a_SOURCES = gprs_ns.c gprs_bssgp.c gprs_llc.c gprs_gmm.c \
		crc24.c gprs_sgsn.c gprs_bssgp_util.c gprs_bssgp_vty.c

osmo_gbproxy_SOURCES = gb_proxy.c gb_proxy_main.c gb_proxy_vty.c \
			gprs_ns.c gprs_ns_vty.c gprs_bssgp_util.c \
			$(top_srcdir)/src/socket.c $(top_srcdir)/src/debug.c
osmo_gbproxy_LDADD = $(top_builddir)/src/libvty.a

osmo_sgsn_SOURCES = sgsn_main.c sgsn_vty.c gprs_ns_vty.c sgsn_libgtp.c \
			$(top_srcdir)/src/socket.c $(top_srcdir)/src/debug.c
osmo_sgsn_LDADD = $(top_builddir)/src/libvty.a libsgsn.a -lgtp
