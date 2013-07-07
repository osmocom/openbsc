AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS)

noinst_LIBRARIES = libbsc.a

libbsc_a_SOURCES =	abis_nm.c abis_nm_vty.c \
			abis_om2000.c abis_om2000_vty.c \
			abis_rsl.c bsc_rll.c \
			paging.c \
			bts_ericsson_rbs2000.c \
			bts_ipaccess_nanobts.c \
			bts_siemens_bs11.c \
			bts_nokia_site.c \
			bts_unknown.c \
			bts_sysmobts.c \
			chan_alloc.c \
			gsm_subscriber_base.c \
			handover_decision_1.c handover_decision_2.c \
			handover_vty.c handover_logic.c meas_rep.c \
			rest_octets.c system_information.c \
			e1_config.c \
			bsc_api.c bsc_msc.c bsc_vty.c \
			gsm_04_08_utils.c \
			bsc_init.c bts_init.c bsc_rf_ctrl.c \
			arfcn_range_encode.c

