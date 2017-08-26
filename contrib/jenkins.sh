#!/usr/bin/env bash
# jenkins build helper script for openbsc.  This is how we build on jenkins.osmocom.org

if ! [ -x "$(command -v osmo-build-dep.sh)" ]; then
	echo "Error: We need to have scripts/osmo-deps.sh from http://git.osmocom.org/osmo-ci/ in PATH !"
	exit 2
fi


set -ex

base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

mkdir "$deps" || true
rm -rf "$inst"

verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"

if [ "x$IU" = "x--enable-iu" ]; then
	sccp_branch="old_sua"
	osmo_iuh_branch="old_sua"
fi

osmo-build-dep.sh libosmocore
osmo-build-dep.sh libosmo-abis
osmo-build-dep.sh libosmo-netif
osmo-build-dep.sh libosmo-sccp $sccp_branch
PARALLEL_MAKE="" osmo-build-dep.sh libsmpp34
osmo-build-dep.sh openggsn

if [ "x$IU" = "x--enable-iu" ]; then
	osmo-build-dep.sh libasn1c
	#osmo-build-dep.sh asn1c aper-prefix # only needed for make regen in osmo-iuh
	osmo-build-dep.sh osmo-iuh $osmo_iuh_branch
fi

set +x
echo
echo
echo
echo " =============================== openbsc ==============================="
echo
set -x

cd "$base"
cd openbsc
autoreconf --install --force
./configure --enable-osmo-bsc --enable-nat $SMPP $MGCP $IU --enable-vty-tests --enable-external-tests
$MAKE $PARALLEL_MAKE
LD_LIBRARY_PATH="$inst/lib" $MAKE check \
  || cat-testlogs.sh
LD_LIBRARY_PATH="$inst/lib" $MAKE distcheck \
  || cat-testlogs.sh
