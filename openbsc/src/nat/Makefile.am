INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMOSCCP_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS)

bin_PROGRAMS = bsc_nat


bsc_nat_SOURCES = bsc_filter.c bsc_mgcp_utils.c bsc_nat.c bsc_nat_utils.c \
		  bsc_nat_vty.c bsc_sccp.c bsc_ussd.c \
		$(top_srcdir)/src/debug.c $(top_srcdir)/src/bsc_msc.c
bsc_nat_LDADD = $(top_builddir)/src/libvty.a \
		$(top_builddir)/src/libmgcp.a $(top_builddir)/src/libbsc.a \
		-lrt $(LIBOSMOSCCP_LIBS)
