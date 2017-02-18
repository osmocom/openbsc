AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBSMPP34_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

EXTRA_DIST = \
	subscr_test.ok \
	bsc_subscr_test.ok \
	bsc_subscr_test.err \
	$(NULL)

noinst_PROGRAMS = \
	subscr_test \
	bsc_subscr_test \
	$(NULL)

subscr_test_SOURCES = \
	subscr_test.c \
	$(NULL)

subscr_test_LDADD = \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libcommon-cs/libcommon-cs.a \
	$(top_builddir)/src/libtrau/libtrau.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBSMPP34_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(NULL)

bsc_subscr_test_SOURCES = \
	bsc_subscr_test.c \
	$(NULL)

bsc_subscr_test_LDADD = \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libcommon-cs/libcommon-cs.a \
	$(top_builddir)/src/libtrau/libtrau.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBSMPP34_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(NULL)
