#!/usr/bin/env python
# Simple server for mgcp... send audit, receive response..

import socket, time

MGCP_GATEWAY_PORT = 2427
MGCP_CALLAGENT_PORT = 2727

rsip_resp = """200 321321332\r\n"""
audit_packet = """AUEP %d 13@mgw MGCP 1.0\r\n"""
crcx_packet = """CRCX %d 14@mgw MGCP 1.0\r\nC: 4a84ad5d25f\r\nL: p:20, a:GSM-EFR, nt:IN\r\nM: recvonly\r\n"""
dlcx_packet = """DLCX %d 14@mgw MGCP 1.0\r\nC: 4a84ad5d25f\r\nI: %d\r\n"""
mdcx_packet = """MDCX %d 14@mgw MGCP 1.0\r\nC: 4a84ad5d25f\r\nI: %d\r\nL: p:20, a:GSM-EFR, nt:IN\r\nM: recvonly\r\n\r\nv=0\r\no=- 258696477 0 IN IP4 172.16.1.107\r\ns=-\r\nc=IN IP4 172.16.1.107\r\nt=0 0\r\nm=audio 6666 RTP/AVP 127\r\na=rtpmap:127 GSM-EFR/8000/1\r\na=ptime:20\r\na=recvonly\r\nm=image 4402 udptl t38\r\na=T38FaxVersion:0\r\na=T38MaxBitRate:14400\r\n"""

def hexdump(src, length=8):
    """Recipe is from http://code.activestate.com/recipes/142812/"""
    result = []
    digits = 4 if isinstance(src, unicode) else 2
    for i in xrange(0, len(src), length):
       s = src[i:i+length]
       hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
       text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
       result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
    return b'\n'.join(result)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("127.0.0.1", MGCP_CALLAGENT_PORT))
server_socket.setblocking(1)

last_ci = 1
def send_and_receive(packet):
    global last_ci
    server_socket.sendto(packet, ("127.0.0.1", MGCP_GATEWAY_PORT))
    try:
        data, addr = server_socket.recvfrom(4096)

        # attempt to store the CI of the response
        list = data.split("\n")
        for item in list:
           if item.startswith("I: "):
               last_ci = int(item[3:])

        print hexdump(data), addr
    except socket.error, e:
        print e
        pass

def generate_tid():
    import random
    return random.randint(0, 65123)



while True:
    send_and_receive(audit_packet % generate_tid())
    send_and_receive(crcx_packet % generate_tid() )
    send_and_receive(mdcx_packet % (generate_tid(), last_ci))
    send_and_receive(dlcx_packet % (generate_tid(), last_ci))

    time.sleep(3)
