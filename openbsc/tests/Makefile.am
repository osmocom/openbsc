SUBDIRS = debug gsm0408 db channel mgcp gprs

if BUILD_NAT
SUBDIRS += bsc-nat
ENABLE_NAT_TEST = echo 'm4_define([ENABLE_NAT_TEST], [1])';
else
ENABLE_NAT_TEST = echo '';
endif


# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(builddir)/package.m4: $(top_srcdir)/configure.ac $(top_builddir)/config.log
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
               $(ENABLE_NAT_TEST) \
             } >'$(builddir)/package.m4'

EXTRA_DIST = testsuite.at $(builddir)/package.m4 $(TESTSUITE)
TESTSUITE = $(builddir)/testsuite

check-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)

installcheck-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
		$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean
	$(RM) -f atconfig
	$(RM) $(TESTSUITE)
	$(RM) $(builddir)/package.m4

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(builddir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
