INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(COVERAGE_LDFLAGS)

noinst_LIBRARIES = libabis.a

libabis_a_SOURCES = e1_input.c e1_input_vty.c \
			input/misdn.c		\
			input/ipaccess.c	\
			input/hsl.c		\
			input/dahdi.c		\
			input/lapd.c

EXTRA_DIST = input/lapd.h
