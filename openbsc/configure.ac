dnl Process this file with autoconf to produce a configure script
AC_INIT([openbsc],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc-devel@lists.openbsc.org])

AM_INIT_AUTOMAKE([dist-bzip2])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB

dnl checks for libraries
AC_SEARCH_LIBS(crypt, crypt,
    [LIBCRYPT="-lcrypt"; AC_DEFINE([VTY_CRYPT_PW], [], [Use crypt functionality of vty.])])
AC_SEARCH_LIBS(gtp_new, gtp,
    [LIBCRYPT="-lgtp"; AC_SUBST([GPRS_LIBGTP], [1])])

AM_CONDITIONAL(HAVE_LIBGTP, test "x$GPRS_LIBGTP" != "x")


AC_ARG_ENABLE([nat], [AS_HELP_STRING([--enable-nat], [Build the BSC NAT. Requires SCCP])],
    [
        PKG_CHECK_MODULES(LIBOSMOSCCP, libosmo-sccp >= 0.0.2)
        osmo_ac_build_nat="yes"
    ],
    [
        osmo_ac_build_nat="no"
    ])
AM_CONDITIONAL(BUILD_NAT, test "x$osmo_ac_build_nat" = "xyes")

# Enable/disable the BSC?
AC_ARG_ENABLE([osmo-bsc], [AS_HELP_STRING([--enable-osmo-bsc], [Build the Osmo BSC])],
    [osmo_ac_build_bsc="$enableval"],[osmo_ac_build_bsc="no"])
if test "$osmo_ac_build_bsc" = "yes" ; then
    PKG_CHECK_MODULES(LIBOSMOSCCP, libosmo-sccp >= 0.0.6)
fi
AM_CONDITIONAL(BUILD_BSC, test "x$osmo_ac_build_bsc" = "xyes")
AC_SUBST(osmo_ac_build_bsc)

PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 0.3.2)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 0.3.0)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 0.3.0)

dnl checks for header files
AC_HEADER_STDC
AC_CHECK_HEADERS(dahdi/user.h,,AC_MSG_WARN(DAHDI input driver will not be built))
AC_CHECK_HEADERS(dbi/dbd.h,,AC_MSG_ERROR(DBI library is not installed))


dnl Checks for typedefs, structures and compiler characteristics

# The following test is taken from WebKit's webkit.m4
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fvisibility=hidden "
AC_MSG_CHECKING([if ${CC} supports -fvisibility=hidden])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes])
        SYMBOL_VISIBILITY="-fvisibility=hidden"],
        AC_MSG_RESULT([no]))
CFLAGS="$saved_CFLAGS"
AC_SUBST(SYMBOL_VISIBILITY)

# Coverage build taken from WebKit's configure.in
AC_MSG_CHECKING([whether to enable code coverage support])
AC_ARG_ENABLE(coverage,
              AC_HELP_STRING([--enable-coverage],
                             [enable code coverage support [default=no]]),
              [],[enable_coverage="no"])
AC_MSG_RESULT([$enable_coverage])
if test "$enable_coverage" = "yes"; then
   COVERAGE_CFLAGS="-ftest-coverage -fprofile-arcs"
   COVERAGE_LDFLAGS="-ftest-coverage -fprofile-arcs"
   AC_SUBST([COVERAGE_CFLAGS])
   AC_SUBST([COVERAGE_LDFLAGS])
fi


dnl Generate the output
AM_CONFIG_HEADER(bscconfig.h)

AC_OUTPUT(
    openbsc.pc
    include/openbsc/Makefile
    include/Makefile
    src/Makefile
    src/libtrau/Makefile
    src/libabis/Makefile
    src/libbsc/Makefile
    src/libctrl/Makefile
    src/libmsc/Makefile
    src/libmgcp/Makefile
    src/libcommon/Makefile
    src/osmo-nitb/Makefile
    src/osmo-bsc/Makefile
    src/osmo-bsc_nat/Makefile
    src/osmo-bsc_mgcp/Makefile
    src/ipaccess/Makefile
    src/utils/Makefile
    src/libgb/Makefile
    src/gprs/Makefile
    tests/Makefile
    tests/debug/Makefile
    tests/gsm0408/Makefile
    tests/db/Makefile
    tests/channel/Makefile
    tests/bsc/Makefile
    tests/bsc-nat/Makefile
    tests/mgcp/Makefile
    tests/si/Makefile
    doc/Makefile
    doc/examples/Makefile
    Makefile)
