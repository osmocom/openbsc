#!/bin/sh

while true;
do
	echo "Kill the osmo-bsc"
	/usr/bin/kill -s SIGUSR2 `pidof osmo-bsc`
	sleep 58s
done
