dnl Process this file with autoconf to produce a configure script
AC_INIT([openbsc],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc-devel@lists.openbsc.org])

AM_INIT_AUTOMAKE([dist-bzip2])
AC_CONFIG_TESTDIR(tests)

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

PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 0.5.3.60)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 0.3.0)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 0.6.0)
PKG_CHECK_MODULES(LIBOSMOABIS, libosmoabis >= 0.1.0)
PKG_CHECK_MODULES(LIBOSMOGB, libosmogb >= 0.5.2)

# Enabke/disable the NAT?
AC_ARG_ENABLE([nat], [AS_HELP_STRING([--enable-nat], [Build the BSC NAT. Requires SCCP])],
    [osmo_ac_build_nat="$enableval"],[osmo_ac_build_nat="no"])
if test "$osmo_ac_build_nat" = "yes" ; then
        PKG_CHECK_MODULES(LIBOSMOSCCP, libosmo-sccp >= 0.0.2)
fi
AM_CONDITIONAL(BUILD_NAT, test "x$osmo_ac_build_nat" = "xyes")
AC_SUBST(osmo_ac_build_nat)

# Enable/disable the BSC?
AC_ARG_ENABLE([osmo-bsc], [AS_HELP_STRING([--enable-osmo-bsc], [Build the Osmo BSC])],
    [osmo_ac_build_bsc="$enableval"])
if test "$osmo_ac_build_bsc" = "yes" ; then
    PKG_CHECK_MODULES(LIBOSMOSCCP, libosmo-sccp >= 0.0.6)
fi
AM_CONDITIONAL(BUILD_BSC, test "x$osmo_ac_build_bsc" = "xyes")

# Enable/disable smpp support in the nitb?
AC_ARG_ENABLE([smpp], [AS_HELP_STRING([--enable-smpp], [Build the SMPP interface])],
    [osmo_ac_build_smpp="$enableval"],[osmo_ac_build_smpp="no"])
if test "$osmo_ac_build_smpp" = "yes" ; then
    PKG_CHECK_MODULES(LIBSMPP34, libsmpp34 >= 1.10)
    AC_DEFINE(BUILD_SMPP, 1, [Define if we want to build SMPP])
fi
AM_CONDITIONAL(BUILD_SMPP, test "x$osmo_ac_build_smpp" = "xyes")
AC_SUBST(osmo_ac_build_smpp)


found_libgtp=yes
PKG_CHECK_MODULES(LIBGTP, libgtp, , found_libgtp=no)
AM_CONDITIONAL(HAVE_LIBGTP, test "$found_libgtp" = yes)

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

AC_DEFUN([CHECK_TM_INCLUDES_TM_GMTOFF], [
  AC_CACHE_CHECK(
    [whether struct tm has tm_gmtoff member],
    osmo_cv_tm_includes_tm_gmtoff,
    [AC_LINK_IFELSE([
      AC_LANG_PROGRAM([
        #include <time.h>
      ], [
        time_t t = time(NULL);
        struct tm* lt = localtime(&t);
        int off = lt->tm_gmtoff;
      ])
    ],
    osmo_cv_tm_includes_tm_gmtoff=yes,
    osmo_cv_tm_includes_tm_gmtoff=no
    )]
  )
  if test "x$osmo_cv_tm_includes_tm_gmtoff" = xyes; then
    AC_DEFINE(HAVE_TM_GMTOFF_IN_TM, 1,
              [Define if struct tm has tm_gmtoff member.])
  fi
])

CHECK_TM_INCLUDES_TM_GMTOFF

AC_ARG_ENABLE([vty_tests],
		AC_HELP_STRING([--enable-vty-tests],
				[Include the VTY tests in make check [default=no]]),
		[enable_vty_tests="$enableval"],[enable_vty_tests="no"])
if test "x$enable_vty_tests" = "xyes" ; then
	AM_PATH_PYTHON
	AC_CHECK_PROG(OSMOTESTVTY_CHECK,osmotestvty.py,yes)
	 if test "x$OSMOTESTVTY_CHECK" != "xyes" ; then
		AC_MSG_ERROR([Please install osmocom-python to run the vty tests.])
	fi
fi
AC_MSG_CHECKING([whether to enable VTY tests])
AC_MSG_RESULT([$enable_vty_tests])
AM_CONDITIONAL(ENABLE_VTY_TESTS, test "x$enable_vty_tests" = "xyes")

dnl Generate the output
AM_CONFIG_HEADER(bscconfig.h)

AC_OUTPUT(
    openbsc.pc
    include/openbsc/Makefile
    include/Makefile
    src/Makefile
    src/libtrau/Makefile
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
    src/gprs/Makefile
    tests/Makefile
    tests/atlocal
    tests/gsm0408/Makefile
    tests/db/Makefile
    tests/channel/Makefile
    tests/bsc-nat/Makefile
    tests/mgcp/Makefile
    tests/gprs/Makefile
    tests/si/Makefile
    tests/abis/Makefile
    tests/smpp/Makefile
    doc/Makefile
    doc/examples/Makefile
    Makefile)
