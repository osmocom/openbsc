AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBCARES_CFLAGS)

EXTRA_DIST = sndcp_xid_test.ok

noinst_PROGRAMS = sndcp_xid_test

sndcp_xid_test_SOURCES = sndcp_xid_test.c

sndcp_xid_test_LDADD = \
	$(top_builddir)/src/gprs/gprs_sndcp_xid.o \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOGB_LIBS) \
	$(LIBCARES_LIBS) \
	$(LIBCRYPTO_LIBS) \
	$(LIBGTP_LIBS) \
	-lrt -lm


