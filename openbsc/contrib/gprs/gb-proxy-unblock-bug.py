#!/usr/bin/env python

"""
demonstrate a unblock bug on the GB Proxy..
"""

bts_ns_reset = "\x02\x00\x81\x01\x01\x82\x1f\xe7\x04\x82\x1f\xe7"
ns_reset_ack = "\x03\x01\x82\x1f\xe7\x04\x82\x1f\xe7"

bts_ns_unblock = "\x06"
ns_unblock_ack = "\x07"

bts_bvc_reset_0 = "\x00\x00\x00\x00\x22\x04\x82\x00\x00\x07\x81\x03\x3b\x81\x02"
ns_bvc_reset_0_ack = "\x00\x00\x00\x00\x23\x04\x82\x00\x00"

bts_bvc_reset_8167 = "\x00\x00\x00\x00\x22\x04\x82\x1f\xe7\x07\x81\x08\x08\x88\x72\xf4\x80\x10\x1c\x00\x9c\x40"


import socket
socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket.bind(("0.0.0.0", 0))
socket.setblocking(1)


import sys
port = int(sys.argv[1])
print "Sending data to port: %d" % port

def send_and_receive(packet):
    socket.sendto(packet, ("127.0.0.1", port))

    try:
        data, addr = socket.recvfrom(4096)
    except socket.error, e:
        print "ERROR", e
        import sys
        sys.exit(0)
    return data

#send stuff once

to_send = [
    (bts_ns_reset, ns_reset_ack, "reset ack"),
    (bts_ns_unblock, ns_unblock_ack, "unblock ack"),
    (bts_bvc_reset_0, ns_bvc_reset_0_ack, "BVCI=0 reset ack"),
]


for (out, inp, type) in to_send:
    res = send_and_receive(out)
    if res != inp:
        print "Failed to get the %s" % type
        sys.exit(-1)

import time
time.sleep(3)
res = send_and_receive(bts_bvc_reset_8167)
print "Sent all messages... check wireshark for the last response"
