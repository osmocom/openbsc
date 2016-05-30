AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(COVERAGE_CFLAGS) \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBSMPP34_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

bin_PROGRAMS = \
	osmo-cscn \
	$(NULL)

noinst_HEADERS = \
	iucs_ranap.h \
	$(NULL)

osmo_cscn_SOURCES = \
	cscn_main.c \
	iucs_ranap.c \
	$(NULL)

osmo_cscn_LDADD = \
	$(top_builddir)/src/libiu/libiu.a \
	$(top_builddir)/src/libmsc/libmsc.a \
	$(top_builddir)/src/libxsc/libxsc.a \
	$(top_builddir)/src/libtrau/libtrau.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBCRYPT) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBSMPP34_LIBS) \
	$(LIBCRYPTO_LIBS) \
	-ldbi \
	$(LIBOSMORANAP_LIBS) \
	$(LIBASN1C_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(NULL)
