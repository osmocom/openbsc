AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)

noinst_LIBRARIES = libfilter.a

libfilter_a_SOURCES = \
	bsc_msg_filter.c \
	bsc_msg_acc.c

