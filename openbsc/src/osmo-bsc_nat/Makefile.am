AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMOSCCP_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBCRYPTO_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

bin_PROGRAMS = \
	osmo-bsc_nat \
	$(NULL)

osmo_bsc_nat_SOURCES = \
	bsc_filter.c \
	bsc_mgcp_utils.c \
	bsc_nat.c \
	bsc_nat_utils.c \
	bsc_nat_vty.c \
	bsc_sccp.c \
	bsc_ussd.c \
	bsc_nat_ctrl.c \
	bsc_nat_rewrite.c \
	bsc_nat_rewrite_trie.c \
	bsc_nat_filter.c \
	$(NULL)

osmo_bsc_nat_LDADD = \
	$(top_builddir)/src/libmgcp/libmgcp.a \
	$(top_builddir)/src/libfilter/libfilter.a \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libcommon-cs/libcommon-cs.a \
	$(top_builddir)/src/libtrau/libtrau.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOSCCP_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(LIBCRYPTO_LIBS) \
	-lrt \
	$(NULL)
