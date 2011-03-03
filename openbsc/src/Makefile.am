INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(COVERAGE_LDFLAGS)

SUBDIRS = common abis mgcp bsc trau osmo-nitb utils ipaccess gprs

# Conditional modules
if BUILD_NAT
SUBDIRS += nat
endif
if BUILD_BSC
SUBDIRS += osmo-bsc
endif

bin_PROGRAMS = bsc_mgcp

bsc_mgcp_SOURCES = mgcp/mgcp_main.c
bsc_mgcp_LDADD = common/libcommon.a mgcp/libmgcp.a $(LIBOSMOVTY_LIBS)
