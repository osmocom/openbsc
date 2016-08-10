AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBCARES_CFLAGS)

EXTRA_DIST = xid_test.ok

noinst_PROGRAMS = xid_test

xid_test_SOURCES = xid_test.c

xid_test_LDADD = \
	$(top_builddir)/src/gprs/gprs_llc_xid.o \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOGB_LIBS) \
	$(LIBCARES_LIBS) \
	$(LIBCRYPTO_LIBS) \
	-lgtp -lrt -lm


