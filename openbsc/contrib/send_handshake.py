#!/usr/bin/env python

import sys

# packages
ACK ="\x00\x01\xfe\x06"
RESET_ACK = "\x00\x13\xfd\x09\x00\x03\x07\x0b\x04\x43\x01\x00\xfe\x04\x43\x5c\x00\xfe\x03\x00\x01\x31"
PAGE = "\x00\x20\xfd\x09\x00\x03\x07\x0b\x04\x43\x01\x00\xfe\x04\x43\x5c\x00\xfe\x10\x00\x0e\x52\x08\x08\x29\x42\x08\x05\x03\x12\x23\x42\x1a\x01\x06"


# simple handshake...
sys.stdout.write(ACK)
sys.stdout.flush()
sys.stdin.read(4)

# wait for some data and send reset ack
sys.stdin.read(21)
sys.stdout.write(RESET_ACK)
sys.stdout.flush()

sys.stdout.write(RESET_ACK)
sys.stdout.flush()

# page a subscriber
sys.stdout.write(PAGE)
sys.stdout.flush()

while True:
    sys.stdin.read(1)

