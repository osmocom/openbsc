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
	db_test.ok \
	db_test.err \
	hlr.sqlite3 \
	$(NULL)

noinst_PROGRAMS = \
	db_test \
	$(NULL)

db_test_SOURCES = \
	db_test.c \
	$(NULL)

db_test_LDADD = \
	$(top_builddir)/src/libmsc/libmsc.a \
	$(top_builddir)/src/libcommon-cs/libcommon-cs.a \
	$(top_builddir)/src/libtrau/libtrau.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(top_builddir)/tests/libiudummy/libiudummy.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBSMPP34_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBCRYPTO_LIBS) \
	-ldbi \
	$(NULL)
