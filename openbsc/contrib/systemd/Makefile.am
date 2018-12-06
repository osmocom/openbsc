EXTRA_DIST = \
  osmo-bsc-mgcp.service \
  osmo-bsc-nat.service \
  osmo-bsc-sccplite.service \
  osmo-nitb.service

if HAVE_SYSTEMD
SYSTEMD_SERVICES = osmo-nitb.service osmo-bsc-mgcp.service

if BUILD_NAT
SYSTEMD_SERVICES += osmo-bsc-nat.service
endif

if BUILD_BSC
SYSTEMD_SERVICES += osmo-bsc-sccplite.service
endif

systemdsystemunit_DATA = $(SYSTEMD_SERVICES)
endif # HAVE_SYSTEMD
