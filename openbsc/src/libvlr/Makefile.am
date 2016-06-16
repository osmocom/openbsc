AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
	$(COVERAGE_CFLAGS) $(LIBCRYPTO_CFLAGS)

noinst_HEADERS = vlr_auth_fsm.h vlr_core.h vlr_lu_fsm.h vlr_access_req_fsm.h

noinst_LIBRARIES = libvlr.a

libvlr_a_SOURCES =	vlr.c vlr_auth_fsm.c vlr_lu_fsm.c vlr_access_req_fsm.c
