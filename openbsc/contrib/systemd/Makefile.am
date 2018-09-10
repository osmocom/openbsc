if HAVE_SYSTEMD
SYSTEMD_SERVICES = osmo-nitb.service osmo-bsc-mgcp.service

if BUILD_NAT
SYSTEMD_SERVICES += osmo-bsc-nat.service
endif

if BUILD_BSC
SYSTEMD_SERVICES += osmo-bsc-sccplite.service
endif

EXTRA_DIST = $(SYSTEMD_SERVICES)
systemdsystemunit_DATA = $(SYSTEMD_SERVICES)
endif # HAVE_SYSTEMD
