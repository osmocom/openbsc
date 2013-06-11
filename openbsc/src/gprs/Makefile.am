AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall -fno-strict-aliasing $(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) $(LIBOSMOGB_CFLAGS) $(COVERAGE_CFLAGS)
OSMO_LIBS = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) \
	    $(LIBOSMOGB_LIBS)

noinst_HEADERS = gprs_sndcp.h

if HAVE_LIBGTP
bin_PROGRAMS = osmo-gbproxy osmo-sgsn
else
bin_PROGRAMS = osmo-gbproxy
endif

osmo_gbproxy_SOURCES = gb_proxy.c gb_proxy_main.c gb_proxy_vty.c
osmo_gbproxy_LDADD = 	$(top_builddir)/src/libcommon/libcommon.a \
			$(OSMO_LIBS)

osmo_sgsn_SOURCES =	gprs_gmm.c gprs_sgsn.c gprs_sndcp.c gprs_sndcp_vty.c \
			sgsn_main.c sgsn_vty.c sgsn_libgtp.c \
			gprs_llc.c gprs_llc_vty.c crc24.c
osmo_sgsn_LDADD = 	$(top_builddir)/src/libcommon/libcommon.a \
			-lgtp $(OSMO_LIBS)
