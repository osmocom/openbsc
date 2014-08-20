AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(COVERAGE_LDFLAGS)

SUBDIRS = libcommon libmgcp libbsc libmsc libtrau osmo-nitb osmo-bsc_mgcp utils ipaccess gprs

# Conditional modules
if BUILD_NAT
SUBDIRS += osmo-bsc_nat
endif
if BUILD_BSC
SUBDIRS += osmo-bsc
endif
