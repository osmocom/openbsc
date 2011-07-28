#!/usr/bin/python

import sys,os
from optparse import OptionParser
import socket
import struct

verbose = False

def prefix_ipa_ctrl_header(data):
	return struct.pack(">HBB", len(data)+1, 0xee, 0) + data

def remove_ipa_ctrl_header(data):
	if (len(data) < 4):
		raise BaseException("Answer too short!")
	(plen, ipa_proto, osmo_proto) = struct.unpack(">HBB", data[:4])
	if (plen + 3 > len(data)):
		print "Warning: Wrong payload length (expected %i, got %i)" % (plen, len(data) - 3)
	if (ipa_proto != 0xee or osmo_proto != 0):
		raise BaseException("Wrong protocol in answer!")

	return data[4:plen+3], data[plen+3:]

def connect(host, port):
	if verbose:
		print "Connecting to host %s:%i" % (host, port)

	sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sck.setblocking(1)
	sck.connect((host, port))
	return sck

def send(sck, data):
	if verbose:
		print "Sending \"%s\"" %(data)
	data = prefix_ipa_ctrl_header(data)
	sck.send(data)

def do_set(var, value, id, sck):
	setmsg = "SET %s %s %s" %(options.id, var, value)
	send(sck, setmsg)

def do_get(var, id, sck):
	getmsg = "GET %s %s" %(options.id, var)
	send(sck, getmsg)

parser = OptionParser("Usage: %prog [options] var [value]")
parser.add_option("-d", "--host", dest="host",
  help="connect to HOST", metavar="HOST")
parser.add_option("-p", "--port", dest="port", type="int",
  help="use PORT", metavar="PORT", default=4249)
parser.add_option("-g", "--get", action="store_true",
  dest="cmd_get", help="perform GET operation")
parser.add_option("-s", "--set", action="store_true",
  dest="cmd_set", help="perform SET operation")
parser.add_option("-i", "--id", dest="id", default="1",
  help="set id manually", metavar="ID")
parser.add_option("-v", "--verbose", action="store_true",
  dest="verbose", help="be verbose", default=False)
parser.add_option("-m", "--monitor", action="store_true",
  dest="monitor", help="monitor the connection for traps", default=False)

(options, args) = parser.parse_args()

verbose = options.verbose

if options.cmd_set and options.cmd_get:
	parser.error("Get and set options are mutually exclusive!")

if not (options.cmd_get or options.cmd_set or options.monitor):
	parser.error("One of -m, -g, or -s must be set")

if not (options.host):
	parser.error("Destination host and port required!")

sock = connect(options.host, options.port)

if options.cmd_set:
	if len(args) < 2:
		parser.error("Set requires var and value arguments")
	do_set(args[0], ' '.join(args[1:]), options.id, sock)

if options.cmd_get:
	if len(args) != 1:
		parser.error("Get requires the var argument")
	do_get(args[0], options.id, sock)

data = sock.recv(1024)
while (len(data)>0):
	(answer, data) = remove_ipa_ctrl_header(data)
	print "Got message:", answer

if options.monitor:
	while (True):
		data = sock.recv(1024)
		if len(data) == 0:
			print "Connection is gone."
			break

		while (len(data)>0):
			(answer, data) = remove_ipa_ctrl_header(data)
			print "Got message:", answer

sock.close()
