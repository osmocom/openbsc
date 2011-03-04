INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(COVERAGE_LDFLAGS)

SUBDIRS = libcommon libabis libmgcp libbsc libtrau osmo-nitb osmo-bsc_mgcp utils ipaccess libgb gprs

# Conditional modules
if BUILD_NAT
SUBDIRS += osmo-bsc_nat
endif
if BUILD_BSC
SUBDIRS += osmo-bsc
endif
