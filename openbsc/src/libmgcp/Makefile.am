AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBBCG729_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(LIBBCG729_LIBS) \
	$(NULL)

noinst_LIBRARIES = \
	libmgcp.a \
	$(NULL)

noinst_HEADERS = \
	g711common.h \
	$(NULL)

libmgcp_a_SOURCES = \
	mgcp_common.c \
	mgcp_protocol.c \
	mgcp_network.c \
	mgcp_vty.c \
	mgcp_osmux.c \
	mgcp_sdp.c \
	mgcpgw_client.c \
	mgcpgw_client_vty.c \
	$(NULL)
if BUILD_MGCP_TRANSCODING
libmgcp_a_SOURCES += \
	mgcp_transcode.c \
	$(NULL)
endif
