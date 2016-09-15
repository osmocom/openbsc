AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBCRYPTO_CFLAGS) \
	$(NULL)

noinst_PROGRAMS = \
	mm_auth_test \
	$(NULL)

EXTRA_DIST = \
	mm_auth_test.ok \
	$(NULL)

mm_auth_test_SOURCES = \
	mm_auth_test.c \
	$(NULL)

mm_auth_test_LDFLAGS = \
	-Wl,--wrap=db_get_authinfo_for_subscr \
	-Wl,--wrap=db_get_lastauthtuple_for_subscr \
	-Wl,--wrap=db_sync_lastauthtuple_for_subscr \
	$(NULL)

mm_auth_test_LDADD = \
	$(top_builddir)/src/libmsc/libmsc.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)
