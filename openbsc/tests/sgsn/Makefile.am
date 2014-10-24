AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS)

EXTRA_DIST = sgsn_test.ok

noinst_PROGRAMS = sgsn_test

sgsn_test_SOURCES = sgsn_test.c
sgsn_test_LDADD = \
	$(top_builddir)/src/gprs/gprs_llc_parse.o \
	$(top_builddir)/src/gprs/gprs_llc.o \
	$(top_builddir)/src/gprs/crc24.o \
	$(top_builddir)/src/gprs/gprs_sndcp.o \
	$(top_builddir)/src/gprs/gprs_gmm.o \
	$(top_builddir)/src/gprs/gprs_sgsn.o \
	$(top_builddir)/src/gprs/sgsn_vty.o \
	$(top_builddir)/src/gprs/sgsn_libgtp.o \
	$(top_builddir)/src/gprs/sgsn_auth.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOGB_LIBS) \
	-lgtp

