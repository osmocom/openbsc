#!/bin/sh
# Evil dial script..

while true;
do
	chat -v -f all_dial < /dev/ttyACM0 > /dev/ttyACM0
	sleep 5s
	chat -v -f hangup < /dev/ttyACM0 > /dev/ttyACM0
	sleep 2s
done

