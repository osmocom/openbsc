AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(NULL)

EXTRA_DIST = \
	oap_client_test.ok \
	oap_client_test.err \
	$(NULL)

if HAVE_LIBGTP
if HAVE_LIBCARES
noinst_PROGRAMS = \
	oap_client_test \
	$(NULL)
endif
endif

oap_client_test_SOURCES = \
	oap_client_test.c \
	$(NULL)

oap_client_test_LDADD = \
	$(top_builddir)/src/gprs/gprs_utils.o \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	-lrt

