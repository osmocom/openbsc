INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) -fno-strict-aliasing
AM_LDFLAGS = $(LIBOSMOCORE_LIBS)

noinst_LIBRARIES = libgb.a

if HAVE_LIBGTP
sbin_PROGRAMS = osmo-gbproxy osmo-sgsn
else
sbin_PROGRAMS = osmo-gbproxy
endif


libgb_a_SOURCES = gprs_ns.c gprs_ns_frgre.c gprs_ns_vty.c \
		  gprs_bssgp.c gprs_bssgp_util.c gprs_bssgp_vty.c \
		  gprs_llc.c gprs_llc_vty.c crc24.c

osmo_gbproxy_SOURCES = gb_proxy.c gb_proxy_main.c gb_proxy_vty.c \
			$(top_srcdir)/src/socket.c $(top_srcdir)/src/debug.c
osmo_gbproxy_LDADD = libgb.a $(top_builddir)/src/libvty.a

osmo_sgsn_SOURCES =	gprs_gmm.c gprs_sgsn.c \
			sgsn_main.c sgsn_vty.c sgsn_libgtp.c \
			$(top_srcdir)/src/socket.c $(top_srcdir)/src/debug.c
osmo_sgsn_LDADD = libgb.a $(top_builddir)/src/libvty.a -lgtp
