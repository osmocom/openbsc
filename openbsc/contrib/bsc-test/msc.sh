#!/bin/sh

while true;
do
	echo "Kill the osmo-bsc-sccplite"
	/usr/bin/kill -s SIGUSR2 `pidof osmo-bsc-sccplite`
	sleep 58s
done
