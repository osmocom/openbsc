AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_srcdir)/src/libmsc
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOSCCP_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

EXTRA_DIST = smpp_test.ok smpp_test.err

noinst_PROGRAMS = smpp_test

smpp_test_SOURCES = smpp_test.c \
	$(top_srcdir)/src/libmsc/smpp_utils.c
smpp_test_LDADD = $(LIBOSMOCORE_LIBS) \
	$(top_srcdir)/src/libcommon/libcommon.a
