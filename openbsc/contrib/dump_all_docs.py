#!/usr/bin/env python

"""
Start the process and dump the documentation to the doc dir. This is
copied from the BTS directory and a fix might need to be applied there
too.
"""

import socket, subprocess, time,os


def dump_doc(end, port, filename):
	sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sck.setblocking(1)
	sck.connect(("localhost", port))
	sck.recv(4096)

	# Now send the command
	sck.send("show online-help\r")
	xml = ""
	while True:
		data = sck.recv(4096)
		xml = "%s%s" % (xml, data)
		if data.endswith(end):
			break

	# Now write everything until the end to the file
	out = open(filename, 'w')
	out.write(xml[18:len(end)*-1])
	out.close()


apps = [
	# The same could be done with an empty config file but this way
	# the example files are properly tested.
	(4242, "src/osmo-nitb/osmo-nitb", "doc/examples/osmo-nitb/nanobts/openbsc.cfg", "OpenBSC", "nitb"),
	(4242, "src/osmo-bsc/osmo-bsc", "doc/examples/osmo-bsc/osmo-bsc.cfg", "OsmoBSC", "bsc"),
	(4243, "src/osmo-bsc_mgcp/osmo-bsc_mgcp", "doc/examples/osmo-bsc_mgcp/mgcp.cfg", "OpenBSC MGCP", "mgcp"),
	(4244, "src/osmo-bsc_nat/osmo-bsc_nat", "doc/examples/osmo-bsc_nat/osmo-bsc_nat.cfg", "OsmoBSCNAT", "nat"), 
	(4246, "src/gprs/osmo-gbproxy", "doc/examples/osmo-gbproxy/osmo-gbproxy.cfg", "OsmoGbProxy", "gbproxy"),
]

# Dump the config of all our apps
for app in apps:
	print "Starting app for %s" % app[4]

	cmd = [app[1], "-c", app[2]]
	proc = subprocess.Popen(cmd, stdin=None, stdout=None)
	time.sleep(1)
	try:
		dump_doc('\r\n%s> ' % app[3], app[0], 'doc/%s_vty_reference.xml' % app[4])
	finally:
		# Clean-up
		proc.kill()
		proc.wait()

