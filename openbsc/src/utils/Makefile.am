INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(COVERAGE_LDFLAGS)

bin_PROGRAMS = bs11_config isdnsync

bs11_config_SOURCES = bs11_config.c rs232.c
bs11_config_LDADD = ../common/libcommon.a ../abis/libabis.a ../bsc/libbsc.a

isdnsync_SOURCES = isdnsync.c
