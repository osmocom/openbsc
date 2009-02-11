INCLUDES = $(all_includes) -I$(top_srcdir)/include
noinst_PROGRAMS = sms_test

sms_test_SOURCES = sms_test.c $(top_srcdir)/src/input/misdn.c \
		   $(top_srcdir)/src/abis_rsl.c $(top_srcdir)/src/abis_nm.c \
		   $(top_srcdir)/src/gsm_04_08.c $(top_srcdir)/src/gsm_data.c \
		$(top_srcdir)/src/gsm_subscriber.c $(top_srcdir)/src/msgb.c \
		$(top_srcdir)/src/select.c $(top_srcdir)/src/chan_alloc.c \
		$(top_srcdir)/src/timer.c $(top_srcdir)/src/debug.c \
		$(top_srcdir)/src/db.c $(top_srcdir)/src/gsm_04_11.c \
		$(top_srcdir)/src/paging.c $(top_srcdir)/src/e1_input.c \
		$(top_srcdir)/src/e1_config.c $(top_srcdir)/src/subchan_demux.c \
		$(top_srcdir)/src/trau_mux.c $(top_srcdir)/src/trau_frame.c

sms_test_LDADD = -ldl -ldbi
