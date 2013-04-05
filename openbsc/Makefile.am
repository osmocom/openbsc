AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
SUBDIRS = doc include src tests

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = openbsc.pc

BUILT_SOURCES = $(top_srcdir)/.version
EXTRA_DIST = git-version-gen osmoappdesc.py
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
