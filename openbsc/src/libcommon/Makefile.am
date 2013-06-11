AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)

noinst_LIBRARIES = libcommon.a

libcommon_a_SOURCES = bsc_version.c common_vty.c debug.c gsm_data.c gsm_data_shared.c socket.c talloc_ctx.c
