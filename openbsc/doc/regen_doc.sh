#!/bin/sh -x

if [ -z "$DOCKER_PLAYGROUND" ]; then
	echo "You need to set DOCKER_PLAYGROUND"
	exit 1
fi

SCRIPT=$(realpath "$0")
MANUAL_DIR=$(dirname "$SCRIPT")/../../manuals

COMMIT=${COMMIT:-$(git log -1 --format=format:%H)}

cd "$DOCKER_PLAYGROUND/scripts" || exit 1

OSMO_NITB_BRANCH=$COMMIT ./regen_doc.sh osmo-nitb 4242 \
	"$MANUAL_DIR/OsmoNITB/chapters/counters_generated.adoc" \
	"$MANUAL_DIR/OsmoNITB/vty/nitb_vty_reference.xml"

OSMO_BSCNAT_BRANCH=$COMMIT ./regen_doc.sh osmo-nitb 4244 \
	"$MANUAL_DIR/OsmoBSCNAT/chapters/counters_generated.adoc" \
	"$MANUAL_DIR/OsmoBSCNAT/vty/nat_vty_reference.xml" \
	"osmo-bsc_nat -c /data/osmo-bsc-nat.cfg"
