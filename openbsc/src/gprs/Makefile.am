INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS)

sbin_PROGRAMS = osmo-gbproxy osmo-sgsn
noinst_LIBRARIES = libsgsn.a

libsgsn_a_SOURCES = gprs_ns.c gprs_bssgp.c gprs_llc.c gsm_04_08_gprs.c \
		crc24.c gprs_sgsn.c

osmo_gbproxy_SOURCES = gb_proxy.c gb_proxy_main.c gb_proxy_vty.c \
			gprs_ns.c $(top_srcdir)/src/socket.c $(top_srcdir)/src/debug.c
osmo_gbproxy_LDADD = $(top_builddir)/src/libvty.a

osmo_sgsn_SOURCES = sgsn_main.c sgsn_vty.c \
			$(top_srcdir)/src/socket.c $(top_srcdir)/src/debug.c
osmo_sgsn_LDADD = $(top_builddir)/src/libvty.a libsgsn.a
