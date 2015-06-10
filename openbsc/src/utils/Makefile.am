AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMOABIS_CFLAGS) $(COVERAGE_CFLAGS) $(SQLITE3_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

noinst_HEADERS = meas_db.h

bin_PROGRAMS = bs11_config isdnsync meas_json
if HAVE_SQLITE3
bin_PROGRAMS += osmo-meas-pcap2db osmo-meas-udp2db
endif
if HAVE_LIBCDK
bin_PROGRAMS += meas_vis
endif

if BUILD_SMPP
noinst_PROGRAMS = smpp_mirror
endif

bs11_config_SOURCES = bs11_config.c
bs11_config_LDADD = $(top_builddir)/src/libbsc/libbsc.a \
		    $(top_builddir)/src/libtrau/libtrau.a \
		    $(top_builddir)/src/libcommon/libcommon.a \
		    $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOABIS_LIBS)

isdnsync_SOURCES = isdnsync.c

smpp_mirror_SOURCES = smpp_mirror.c
smpp_mirror_LDADD = $(top_builddir)/src/libcommon/libcommon.a \
		    $(LIBOSMOCORE_LIBS) $(LIBSMPP34_LIBS)

meas_vis_SOURCES = meas_vis.c
meas_vis_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) -lcdk -lncurses
meas_vis_CFLAGS = $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS)

meas_json_SOURCES = meas_json.c
meas_json_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)
meas_json_CFLAGS = $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS)

osmo_meas_pcap2db_SOURCES = meas_pcap2db.c meas_db.c
osmo_meas_pcap2db_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) -lpcap $(SQLITE3_LIBS)
osmo_meas_pcap2db_CFLAGS = $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS)

osmo_meas_udp2db_SOURCES = meas_udp2db.c meas_db.c
osmo_meas_udp2db_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(SQLITE3_LIBS)
osmo_meas_udp2db_CFLAGS = $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS)
