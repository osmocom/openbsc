#!/usr/bin/env python2.7

"""
AGPLv3+ 2016 Copyright Holger Hans Peter Freyther

Example of how to connect to the USSD side-channel and how to respond
with a fixed message.
"""

import socket
import struct

ussdSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ussdSocket.connect(('127.0.0.1', 5001))

def send_dt1(dstref, data):
    dlen = struct.pack('B', len(data)).encode('hex')
    hex = '06' + dstref.encode('hex') + '00' + '01' + dlen + data.encode('hex')
    pdata = hex.decode('hex')
    out = struct.pack('>HB', len(pdata), 0xfd) + pdata
    ussdSocket.send(out)

def send_rel(srcref, dstref):
    hex = '04' + dstref.encode('hex') + srcref.encode('hex') + '000100'
    pdata = hex.decode('hex')
    out = struct.pack('>HB', len(pdata), 0xfd) + pdata
    ussdSocket.send(out)

def recv_one():
    plen = ussdSocket.recv(3)
    (plen,ptype) = struct.unpack(">HB", plen)
    data = ussdSocket.recv(plen)

    return ptype, data

# Assume this is the ID request
data = ussdSocket.recv(4)
ussdSocket.send("\x00\x08\xfe\x05\x00" + "\x05\x01" + "ussd")
#                      ^len                ^len of tag ... and ignore

# Expect a fake message. see struct ipac_msgt_sccp_state
ptype, data = recv_one()
print("%d %s" % (ptype, data.encode('hex')))
(srcref, dstref, transid, invokeid) = struct.unpack("<3s3sBB", data[1:9])
print("New transID %d invoke %d" % (transid, invokeid))

# Expect a the invocation.. todo.. extract invoke id
ptype, data = recv_one()
print("%d %s" % (ptype, data.encode('hex')))

# Reply with BSSAP + GSM 04.08 + MAP portion
#                                    00 == invoke id     0f == DCS
res = "01002a9b2a0802e1901c22a220020100301b02013b301604010f041155e7d2f9bc3a41412894991c06a9c9a713"
send_dt1(dstref, res.decode('hex'))

clear = "000420040109"
send_dt1(dstref, clear.decode('hex'))

# should be the clear complete
send_rel(srcref, dstref)

# Give it some time to handle connection shutdown properly
print("Gracefully sleeping")
import time
time.sleep(3)
