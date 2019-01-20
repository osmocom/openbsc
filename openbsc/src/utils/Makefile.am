AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(SQLITE3_CFLAGS) \
	$(LIBSMPP34_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

bin_PROGRAMS = \
	bs11_config \
	isdnsync \
	$(NULL)

if BUILD_SMPP
noinst_PROGRAMS = \
	smpp_mirror \
	$(NULL)
endif

bs11_config_SOURCES = \
	bs11_config.c \
	$(NULL)

bs11_config_LDADD = \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libcommon-cs/libcommon-cs.a \
	$(top_builddir)/src/libtrau/libtrau.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(NULL)

isdnsync_SOURCES = \
	isdnsync.c \
	$(NULL)

smpp_mirror_SOURCES = \
	smpp_mirror.c \
	$(NULL)

smpp_mirror_LDADD = \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBSMPP34_LIBS) \
	$(NULL)
