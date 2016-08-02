#!/usr/bin/python2

mod_license = '''
/*
 * Copyright (C) 2016 sysmocom s.f.m.c. GmbH
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
'''

import sys, argparse, random, logging, tornado.ioloop, tornado.web, tornado.tcpclient, tornado.httpclient, eventsource, bsc_control
from eventsource import listener, request

'''
N. B: this is not an example of building proper REST API or building secure web application.
It's only purpose is to illustrate conversion of Osmocom's Control Interface to web-friendly API.
Exposing this to Internet while connected to production network might lead to all sorts of mischief and mayhem
from NSA' TAO breaking into your network to zombie apocalypse. Do NOT do that.
'''

token = None
stream = None
url = None

'''
Returns json according to following schema - see http://json-schema.org/documentation.html for details:
{
        "title": "Ctrl Schema",
        "type": "object",
        "properties": {
                "variable": {
                        "type": "string"
                },
                "varlue": {
                        "type": "string"
                }
        },
        "required": ["interface", "variable", "value"]
}
Example validation from command-line:
json validate --schema-file=schema.json --document-file=data.json
The interface is represented as string because it might look different for IPv4 vs v6.
'''

def read_header(data):
	t_length = bsc_control.ipa_ctrl_header(data)
	if (t_length):
		stream.read_bytes(t_length - 1, callback = read_trap)
	else:
		print >> sys.stderr, "protocol error: length missing in %s!" % data

@tornado.gen.coroutine
def read_trap(data):
	(t, z, v, p) = data.split()
	if (t != 'TRAP' or int(z) != 0):
		print >> sys.stderr, "protocol error: TRAP != %s or 0! = %d" % (t, int(z))
	else:
		yield tornado.httpclient.AsyncHTTPClient().fetch(tornado.httpclient.HTTPRequest(url = "%s/%s/%s" % (url, "ping", token),
												method = 'POST',
												headers = {'Content-Type': 'application/json'},
												body = tornado.escape.json_encode({ 'variable' : v, 'value' : p })))
		stream.read_bytes(4, callback = read_header)

@tornado.gen.coroutine
def trap_setup(host, port, target_host, target_port, tk):
	global stream
	global url
	global token
	token = tk
	url = "http://%s:%s/sse" % (host, port)
	stream = yield tornado.tcpclient.TCPClient().connect(target_host, target_port)
	stream.read_bytes(4, callback = read_header)

def get_v(s, v):
	return { 'variable' : v, 'value' : bsc_control.get_var(s, tornado.escape.native_str(v)) }

class CtrlHandler(tornado.web.RequestHandler):
	def initialize(self):
		self.skt = bsc_control.connect(self.settings['ctrl_host'], self.settings['ctrl_port'])

	def get(self, v):
		self.write(get_v(self.skt, v))

	def post(self):
		self.write(get_v(self.skt, self.get_argument("variable")))

class SetCtrl(CtrlHandler):
	def get(self, var, val):
		bsc_control.set_var(self.skt, tornado.escape.native_str(var), tornado.escape.native_str(val))
		super(SetCtrl, self).get(tornado.escape.native_str(var))

	def post(self):
		bsc_control.set_var(self.skt, tornado.escape.native_str(self.get_argument("variable")), tornado.escape.native_str(self.get_argument("value")))
		super(SetCtrl, self).post()

class Slash(tornado.web.RequestHandler):
	def get(self):
		self.write('<html><head><title>%s</title></head><body>Using Tornado framework v%s'
				'<form action="/get" method="POST">'
					'<input type="text" name="variable">'
					'<input type="submit" value="GET">'
				'</form>'
				'<form action="/set" method="POST">'
					'<input type="text" name="variable">'
					'<input type="text" name="value">'
					'<input type="submit" value="SET">'
				'</form>'
				'</body></html>' % ("Osmocom Control Interface Proxy", tornado.version))

if __name__ == '__main__':
	p = argparse.ArgumentParser(description='Osmocom Control Interface proxy.')
	p.add_argument('-c', '--control-port', type = int, default = 4252, help = "Target Control Interface port")
	p.add_argument('-a', '--control-host', default = 'localhost', help = "Target Control Interface adress")
	p.add_argument('-b', '--host', default = 'localhost', help = "Adress to bind proxy's web interface")
	p.add_argument('-p', '--port', type = int, default = 6969, help = "Port to bind proxy's web interface")
	p.add_argument('-d', '--debug', action='store_true', help = "Activate debugging (default off)")
	p.add_argument('-t', '--token', default = 'osmocom', help = "Token to be used by SSE client in URL e. g. http://127.0.0.1:8888/poll/osmocom where 'osmocom' is default token value")
	p.add_argument('-k', '--keepalive', type = int, default = 5000, help = "Timeout betwwen keepalive messages, in milliseconds, defaults to 5000")
	args = p.parse_args()
	random.seed()
	tornado.netutil.Resolver.configure('tornado.netutil.ThreadedResolver') # Use non-blocking resolver
	logging.basicConfig()
	application = tornado.web.Application([
		(r"/", Slash),
		(r"/get", CtrlHandler),
		(r"/get/(.*)", CtrlHandler),
		(r"/set", SetCtrl),
		(r"/set/(.*)/(.*)", SetCtrl),
		(r"/sse/(.*)/(.*)", listener.EventSourceHandler, dict(event_class = listener.JSONIdEvent, keepalive = args.keepalive)),
	], debug = args.debug, ctrl_host = args.control_host, ctrl_port = args.control_port)
	application.listen(address = args.host, port = args.port)
	trap_setup(args.host, args.port, application.settings['ctrl_host'], application.settings['ctrl_port'], args.token)
	tornado.ioloop.IOLoop.instance().start()
