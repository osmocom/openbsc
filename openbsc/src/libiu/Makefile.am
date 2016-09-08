AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(COVERAGE_CFLAGS) \
	$(LIBCRYPTO_CFLAGS) \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(NULL)

noinst_LIBRARIES = \
	libiu.a \
	$(NULL)

libiu_a_SOURCES = \
	iu.c \
	iu_vty.c \
	$(NULL)

