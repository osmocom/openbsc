INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

bin_PROGRAMS = bs11_config isdnsync

bs11_config_SOURCES = bs11_config.c rs232.c
bs11_config_LDADD = $(top_builddir)/src/libcommon/libcommon.a \
		    $(top_builddir)/src/libabis/libabis.a \
		    $(top_builddir)/src/libbsc/libbsc.a \
		    $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)

isdnsync_SOURCES = isdnsync.c
