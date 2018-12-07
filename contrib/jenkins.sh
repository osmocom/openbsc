#!/bin/sh -ex
# jenkins build helper script for openbsc.  This is how we build on jenkins.osmocom.org
#
# environment variables:
# * IU: configure 3G support (values: "--enable-iu", "--disable-iu")
# * MGCP: configure transcoding for MGCP (values: "--enable-mgcp-transcoding", "--disable-mgcp-transcoding")
# * SMPP: configure the SMPP interface (values: "--enable-smpp", "--disable-smpp")
# * WITH_MANUALS: build manual PDFs if set to "1"
# * PUBLISH: upload manuals after building if set to "1" (ignored without WITH_MANUALS = "1")
#

osmo-clean-workspace.sh

artifact_deps() {

	x="$($1 libosmocore)"
	x="${x}_$($1 libosmo-abis)"
	x="${x}_$($1 libosmo-netif)"
	x="${x}_$($1 libosmo-sccp "$sccp_branch")"
	x="${x}_$($1 libsmpp34)"
	x="${x}_$($1 openggsn)"

	if [ "x$IU" = "x--enable-iu" ]; then
		x="${x}_$($1 libasn1c)"
		x="${x}_$($1 osmo-iuh "$osmo_iuh_branch")"
	fi

	echo "${x}.tar.gz"
}

build_deps() {

	osmo-build-dep.sh libosmocore master ac_cv_path_DOXYGEN=false
	verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")
	osmo-build-dep.sh libosmo-abis
	osmo-build-dep.sh libosmo-netif
	osmo-build-dep.sh libosmo-sccp "$sccp_branch"
	PARALLEL_MAKE=-j1 osmo-build-dep.sh libsmpp34
	osmo-build-dep.sh openggsn

	if [ "x$IU" = "x--enable-iu" ]; then
		osmo-build-dep.sh libasn1c
		osmo-build-dep.sh osmo-iuh "$osmo_iuh_branch"
	fi
}

build_project() {

	cd "$base/openbsc"

	autoreconf --install --force

	./configure "$SMPP" "$MGCP" "$IU" \
		--enable-osmo-bsc \
		--enable-nat  \
		--enable-vty-tests \
		--enable-external-tests

	"$MAKE" $PARALLEL_MAKE
	"$MAKE" check || cat-testlogs.sh
	"$MAKE" distcheck || cat-testlogs.sh
}

if [ "x$IU" = "x--enable-iu" ]; then
        sccp_branch="old_sua"
        osmo_iuh_branch="old_sua"
fi

. osmo-build.sh

# Build and publish manuals
if [ "$WITH_MANUALS" = "1" ]; then
	# Build all manuals first
	osmo-build-dep.sh osmo-gsm-manuals
	for dir in "$base"/manuals/*/; do
		make -C "$dir"
	done

	# Run 'make check' for the OsmoNITB manuals.
	# The other dirs only have VTY references, so there is no 'make check' target for them.
	make -C "$base/manuals/OsmoNITB" check

	# Publish all at once
	if [ "$PUBLISH" = "1" ]; then
		for dir in "$base"/manuals/*/; do
			make -C "$dir" publish
		done
	fi
fi

osmo-clean-workspace.sh
