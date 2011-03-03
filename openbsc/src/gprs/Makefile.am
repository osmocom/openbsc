INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall -fno-strict-aliasing $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS) $(COVERAGE_LDFLAGS)

noinst_LIBRARIES = libgb.a
noinst_HEADERS = gprs_sndcp.h

if HAVE_LIBGTP
bin_PROGRAMS = osmo-gbproxy osmo-sgsn
else
bin_PROGRAMS = osmo-gbproxy
endif


libgb_a_SOURCES = gprs_ns.c gprs_ns_frgre.c gprs_ns_vty.c \
		  gprs_bssgp.c gprs_bssgp_util.c gprs_bssgp_vty.c \
		  gprs_llc.c gprs_llc_vty.c crc24.c

osmo_gbproxy_SOURCES = gb_proxy.c gb_proxy_main.c gb_proxy_vty.c
osmo_gbproxy_LDADD = libgb.a $(top_builddir)/src/common/libcommon.a

osmo_sgsn_SOURCES =	gprs_gmm.c gprs_sgsn.c gprs_sndcp.c gprs_sndcp_vty.c \
			sgsn_main.c sgsn_vty.c sgsn_libgtp.c 
osmo_sgsn_LDADD = libgb.a $(top_builddir)/src/common/libcommon.a -lgtp
