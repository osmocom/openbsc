dnl Process this file with autoconf to produce a configure script
AC_INIT([openbsc],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc@lists.osmocom.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE([dist-bzip2])
AC_CONFIG_TESTDIR(tests)

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT

dnl check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

dnl check for AX_CHECK_COMPILE_FLAG
m4_ifdef([AX_CHECK_COMPILE_FLAG], [], [
	AC_MSG_ERROR([Please install autoconf-archive; re-run 'autoreconf -fi' for it to take effect.])
	])

dnl checks for libraries
AC_SEARCH_LIBS([dlopen], [dl dld], [LIBRARY_DL="$LIBS";LIBS=""])
AC_SUBST(LIBRARY_DL)


PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 0.9.5)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 0.3.0)
PKG_CHECK_MODULES(LIBOSMOCTRL, libosmoctrl)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 0.9.5)
PKG_CHECK_MODULES(LIBOSMOABIS, libosmoabis >= 0.2.0)
PKG_CHECK_MODULES(LIBOSMOGB, libosmogb >= 0.6.4)
PKG_CHECK_MODULES(LIBOSMONETIF, libosmo-netif >= 0.0.1)
PKG_CHECK_MODULES(LIBCRYPTO, libcrypto >= 0.9.5)

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
    [osmo_ac_build_bsc="$enableval"],[osmo_ac_build_bsc="no"])
if test "$osmo_ac_build_bsc" = "yes" ; then
    PKG_CHECK_MODULES(LIBOSMOSCCP, libosmo-sccp >= 0.0.6)
fi
AM_CONDITIONAL(BUILD_BSC, test "x$osmo_ac_build_bsc" = "xyes")
AC_SUBST(osmo_ac_build_bsc)

# Enable/disable smpp support in the nitb?
AC_ARG_ENABLE([smpp], [AS_HELP_STRING([--enable-smpp], [Build the SMPP interface])],
    [osmo_ac_build_smpp="$enableval"],[osmo_ac_build_smpp="no"])
if test "$osmo_ac_build_smpp" = "yes" ; then
    PKG_CHECK_MODULES(LIBSMPP34, libsmpp34 >= 1.10)
    AC_DEFINE(BUILD_SMPP, 1, [Define if we want to build SMPP])
fi
AM_CONDITIONAL(BUILD_SMPP, test "x$osmo_ac_build_smpp" = "xyes")
AC_SUBST(osmo_ac_build_smpp)

# Enable/disable transcoding within osmo-bsc_mgcp?
AC_ARG_ENABLE([mgcp-transcoding], [AS_HELP_STRING([--enable-mgcp-transcoding], [Build the MGCP gateway with internal transcoding enabled.])],
    [osmo_ac_mgcp_transcoding="$enableval"],[osmo_ac_mgcp_transcoding="no"])
AC_ARG_WITH([g729], [AS_HELP_STRING([--with-g729], [Enable G.729 encoding/decoding.])], [osmo_ac_with_g729="$withval"],[osmo_ac_with_g729="no"])

if test "$osmo_ac_mgcp_transcoding" = "yes" ; then
    AC_SEARCH_LIBS([gsm_create], [gsm], [LIBRARY_GSM="$LIBS";LIBS=""], [AC_MSG_ERROR([--enable-mgcp-transcoding: cannot find usable libgsm])])
    AC_SUBST(LIBRARY_GSM)
    if test "$osmo_ac_with_g729" = "yes" ; then
	PKG_CHECK_MODULES(LIBBCG729, libbcg729 >= 0.1, [AC_DEFINE([HAVE_BCG729], [1], [Use bgc729 decoder/encoder])])
    fi
    AC_DEFINE(BUILD_MGCP_TRANSCODING, 1, [Define if we want to build the MGCP gateway with transcoding support])
fi
AM_CONDITIONAL(BUILD_MGCP_TRANSCODING, test "x$osmo_ac_mgcp_transcoding" = "xyes")
AC_SUBST(osmo_ac_mgcp_transcoding)

# Enable/disable 3G aka IuPS + IuCS support?
AC_ARG_ENABLE([iu], [AS_HELP_STRING([--enable-iu], [Build 3G support, aka IuPS and IuCS interfaces])],
    [osmo_ac_iu="$enableval"],[osmo_ac_iu="no"])
if test "x$osmo_ac_iu" = "xyes" ; then
    PKG_CHECK_MODULES(LIBASN1C, libasn1c) # TODO version?
    PKG_CHECK_MODULES(LIBOSMORANAP, libosmo-ranap) # TODO version?
    PKG_CHECK_MODULES(LIBOSMOSIGTRAN, libosmo-sigtran) # TODO version?
    AC_DEFINE(BUILD_IU, 1, [Define if we want to build IuPS and IuCS interfaces support])
fi
AM_CONDITIONAL(BUILD_IU, test "x$osmo_ac_iu" = "xyes")
AC_SUBST(osmo_ac_iu)


found_libgtp=yes
PKG_CHECK_MODULES(LIBGTP, libgtp >= 0.92, , found_libgtp=no)
AM_CONDITIONAL(HAVE_LIBGTP, test "$found_libgtp" = yes)
AC_SUBST(found_libgtp)

found_libcares=yes
PKG_CHECK_MODULES([LIBCARES], [libcares], [], [found_libcares=no])
AM_CONDITIONAL(HAVE_LIBCARES, test "$found_libcares" = yes)
AC_SUBST(found_libcares)

found_libgtp_and_libcares=no
if test "$found_libgtp" = "yes" -a "$found_libcares" = "yes"; then
    found_libgtp_and_libcares=yes
fi
AC_SUBST(found_libgtp_and_libcares)

dnl checks for header files
AC_HEADER_STDC
AC_CHECK_HEADERS(dbi/dbd.h,,AC_MSG_ERROR(DBI library is not installed))

found_pcap=yes
AC_CHECK_HEADERS(pcap/pcap.h,,found_pcap=no)
AM_CONDITIONAL(HAVE_PCAP, test "$found_pcap" = yes)

found_cdk=yes
AC_CHECK_HEADERS(cdk/cdk.h,,found_cdk=no)
AM_CONDITIONAL(HAVE_LIBCDK, test "$found_cdk" = yes)

found_sqlite3=yes
PKG_CHECK_MODULES(SQLITE3, sqlite3, ,found_sqlite3=no)
AM_CONDITIONAL(HAVE_SQLITE3, test "$found_sqlite3" = yes)
AC_SUBST(found_sqlite3)


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

AX_CHECK_COMPILE_FLAG([-Werror=implicit], [CFLAGS="$CFLAGS -Werror=implicit"])
AX_CHECK_COMPILE_FLAG([-Werror=maybe-uninitialized], [CFLAGS="$CFLAGS -Werror=maybe-uninitialized"])
AX_CHECK_COMPILE_FLAG([-Werror=memset-transposed-args], [CFLAGS="$CFLAGS -Werror=memset-transposed-args"])
AX_CHECK_COMPILE_FLAG([-Werror=null-dereference], [CFLAGS="$CFLAGS -Werror=null-dereference"])
AX_CHECK_COMPILE_FLAG([-Werror=sizeof-array-argument], [CFLAGS="$CFLAGS -Werror=sizeof-array-argument"])
AX_CHECK_COMPILE_FLAG([-Werror=sizeof-pointer-memaccess], [CFLAGS="$CFLAGS -Werror=sizeof-pointer-memaccess"])

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
				[Include the VTY/CTRL tests in make check (deprecated)
				[default=no]]),
		[enable_ext_tests="$enableval"],[enable_ext_tests="no"])
AC_ARG_ENABLE([external_tests],
		AC_HELP_STRING([--enable-external-tests],
				[Include the VTY/CTRL tests in make check [default=no]]),
		[enable_ext_tests="$enableval"],[enable_ext_tests="no"])
if test "x$enable_ext_tests" = "xyes" ; then
	AM_PATH_PYTHON
	AC_CHECK_PROG(OSMOTESTEXT_CHECK,osmotestvty.py,yes)
	 if test "x$OSMOTESTEXT_CHECK" != "xyes" ; then
		AC_MSG_ERROR([Please install osmocom-python to run the VTY/CTRL tests.])
	fi
fi
AC_MSG_CHECKING([whether to enable VTY/CTRL tests])
AC_MSG_RESULT([$enable_ext_tests])
AM_CONDITIONAL(ENABLE_EXT_TESTS, test "x$enable_ext_tests" = "xyes")

dnl Generate the output
AM_CONFIG_HEADER(bscconfig.h)

AC_OUTPUT(
    openbsc.pc
    include/openbsc/Makefile
    include/Makefile
    src/Makefile
    src/libtrau/Makefile
    src/libbsc/Makefile
    src/libmsc/Makefile
    src/libmgcp/Makefile
    src/libcommon/Makefile
    src/libfilter/Makefile
    src/libiu/Makefile
    src/libcommon-cs/Makefile
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
    tests/bsc/Makefile
    tests/bsc-nat/Makefile
    tests/bsc-nat-trie/Makefile
    tests/mgcp/Makefile
    tests/gprs/Makefile
    tests/gbproxy/Makefile
    tests/abis/Makefile
    tests/smpp/Makefile
    tests/trau/Makefile
    tests/sgsn/Makefile
    tests/subscr/Makefile
    tests/oap/Makefile
    tests/gtphub/Makefile
    tests/mm_auth/Makefile
    tests/xid/Makefile
    tests/sndcp_xid/Makefile
    tests/slhc/Makefile
    tests/v42bis/Makefile
    tests/nanobts_omlattr/Makefile
    doc/Makefile
    doc/examples/Makefile
    Makefile)
