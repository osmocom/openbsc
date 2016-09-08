AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_srcdir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_FLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBOSMOSCCP_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBBCG729_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

EXTRA_DIST = \
	mgcp_test.ok \
	mgcp_transcoding_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	mgcp_test \
	$(NULL)
if BUILD_MGCP_TRANSCODING
noinst_PROGRAMS += \
	mgcp_transcoding_test \
	$(NULL)
endif

mgcp_test_SOURCES = \
	mgcp_test.c \
	$(NULL)

mgcp_test_LDADD = \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libmgcp/libmgcp.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOSCCP_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBRARY_DL) \
	$(LIBOSMONETIF_LIBS) \
	-lrt \
	-lm  \
	$(NULL)

mgcp_transcoding_test_SOURCES = \
	mgcp_transcoding_test.c \
	$(NULL)

mgcp_transcoding_test_LDADD = \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libmgcp/libmgcp.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBBCG729_LIBS) \
	$(LIBOSMOSCCP_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBRARY_DL) \
	$(LIBOSMONETIF_LIBS) \
	$(LIBRARY_GSM) \
	-lrt \
	-lm \
	$(NULL)
