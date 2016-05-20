AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(NULL)

noinst_LIBRARIES = libiudummy.a

libiudummy_a_SOURCES = \
	iudummy.c \
	$(NULL)
