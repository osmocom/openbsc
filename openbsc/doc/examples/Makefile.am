
OSMOCONF_FILES = \
	osmo-nitb/sysmobts/osmo-nitb.cfg \
	osmo-bsc_mgcp/osmo-bsc-mgcp.cfg

if BUILD_NAT
OSMOCONF_FILES += osmo-bsc_nat/osmo-bsc-nat.cfg
endif

if BUILD_BSC
OSMOCONF_FILES += osmo-bsc-sccplite/osmo-bsc-sccplite.cfg
endif

osmoconfdir = $(sysconfdir)/osmocom
osmoconf_DATA = $(OSMOCONF_FILES)

EXTRA_DIST = $(OSMOCONF_FILES)

CFG_FILES = find $(srcdir) -name '*.cfg*' | sed -e 's,^$(srcdir),,'

dist-hook:
	for f in $$($(CFG_FILES)); do \
		j="$(distdir)/$$f" && \
		mkdir -p "$$(dirname $$j)" && \
		$(INSTALL_DATA) $(srcdir)/$$f $$j; \
	done

install-data-hook:
	for f in $$($(CFG_FILES)); do \
		j="$(DESTDIR)$(docdir)/examples/$$f" && \
		mkdir -p "$$(dirname $$j)" && \
		$(INSTALL_DATA) $(srcdir)/$$f $$j; \
	done

uninstall-hook:
	@$(PRE_UNINSTALL)
	for f in $$($(CFG_FILES)); do \
		j="$(DESTDIR)$(docdir)/examples/$$f" && \
		$(RM) $$j; \
	done
