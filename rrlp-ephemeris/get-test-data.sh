#!/bin/sh

DEV=$1
OUTF=$2

# Change mode
echo -en "\$PUBX,41,1,0001,0001,9600,0*14\r\n" > ${DEV}

# Wait a little
sleep 2

# Start dump
echo -en "\xb5\x62\x01\x02\x00\x00\x03\x0a" | \
	socat -t5 ${DEV},b9600,raw,clocal=1,echo=0 - > ${OUTF}
echo -en "\xb5\x62\x0b\x10\x00\x00\x1b\x5c" | \
	socat -t10 ${DEV},b9600,raw,clocal=1,echo=0 - >> ${OUTF}

