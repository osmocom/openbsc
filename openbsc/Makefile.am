AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

## FIXME: automake >= 1.13 or autoconf >= 2.70 provide better suited AC_CONFIG_MACRO_DIRS for configure.ac
## remove line below when OE toolchain is updated to version which include those
ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

SUBDIRS = \
	doc \
	include \
	src \
	tests \
	contrib \
	$(NULL)

BUILT_SOURCES = $(top_srcdir)/.version
EXTRA_DIST = git-version-gen osmoappdesc.py .version

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

@RELMAKE@

$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
