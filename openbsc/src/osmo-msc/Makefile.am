INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(COVERAGE_LDFLAGS)

bin_PROGRAMS = osmo-nitb

osmo_nitb_SOURCES = osmo_msc_main.c osmo_msc_stubs.c \
		$(top_srcdir)/src/libbsc/gsm_subscriber_base.c \
		$(top_srcdir)/src/libbsc/transaction.c
osmo_nitb_LDADD = -ldl -ldbi $(LIBCRYPT) $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) \
		$(top_builddir)/src/libmsc/libmsc.a \
		$(top_builddir)/src/libcommon/libcommon.a
