SUBDIRS = \
	gsm0408 \
	db \
	channel \
	mgcp \
	gprs \
	abis \
	gbproxy \
	trau \
	subscr \
	mm_auth \
	nanobts_omlattr \
	$(NULL)

if BUILD_NAT
SUBDIRS += \
	bsc-nat \
	bsc-nat-trie \
	$(NULL)
endif
if BUILD_BSC
SUBDIRS += \
	bsc \
	$(NULL)
endif
if BUILD_SMPP
SUBDIRS += \
	smpp \
	$(NULL)
endif
if HAVE_LIBGTP
SUBDIRS += \
	gtphub \
	$(NULL)

if HAVE_LIBCARES
SUBDIRS += \
	sgsn \
	oap \
	xid \
	sndcp_xid \
	slhc \
	v42bis \
	$(NULL)
endif
endif

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
               echo '# Signature of the current package.' && \
               echo 'm4_define([AT_PACKAGE_NAME],' && \
               echo '  [$(PACKAGE_NAME)])' && \
               echo 'm4_define([AT_PACKAGE_TARNAME],' && \
               echo '  [$(PACKAGE_TARNAME)])' && \
               echo 'm4_define([AT_PACKAGE_VERSION],' && \
               echo '  [$(PACKAGE_VERSION)])' && \
               echo 'm4_define([AT_PACKAGE_STRING],' && \
               echo '  [$(PACKAGE_STRING)])' && \
               echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
               echo '  [$(PACKAGE_BUGREPORT)])'; \
               echo 'm4_define([AT_PACKAGE_URL],' && \
               echo '  [$(PACKAGE_URL)])'; \
             } >'$(srcdir)/package.m4'

EXTRA_DIST = \
	testsuite.at \
	$(srcdir)/package.m4 \
	$(TESTSUITE) \
	vty_test_runner.py \
	ctrl_test_runner.py \
	smpp_test_runner.py \
	$(NULL)

TESTSUITE = $(srcdir)/testsuite

DISTCLEANFILES = \
	atconfig \
	$(NULL)

if ENABLE_EXT_TESTS
python-tests: $(BUILT_SOURCES)
	osmotestvty.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v
	osmotestconfig.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v
	$(PYTHON) $(srcdir)/vty_test_runner.py -w $(abs_top_builddir) -v
	$(PYTHON) $(srcdir)/ctrl_test_runner.py -w $(abs_top_builddir) -v
if BUILD_SMPP
	$(PYTHON) $(srcdir)/smpp_test_runner.py -w $(abs_top_builddir) -v
endif
	rm -f $(top_builddir)/hlr.sqlite3
else
python-tests: $(BUILT_SOURCES)
	echo "Not running python-based tests (determined at configure-time)"
endif

check-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)
	$(MAKE) $(AM_MAKEFLAGS) python-tests

installcheck-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
		$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
