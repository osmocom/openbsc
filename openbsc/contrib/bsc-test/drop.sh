#!/bin/sh

while true;
do
	echo "Going to drop the OML connection"
	./drop-oml.sh | telnet 127.0.0.1 4242
	sleep 58m
done
