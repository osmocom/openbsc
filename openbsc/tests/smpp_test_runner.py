#!/usr/bin/env python

# (C) 2014 by Holger Hans Peter Freyther
# based on vty_test_runner.py:
# (C) 2013 by Katerina Barone-Adesi <kat.obsc@gmail.com>
# (C) 2013 by Holger Hans Peter Freyther
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import time
import unittest
import socket

import osmopy.obscvty as obscvty
import osmopy.osmoutil as osmoutil

confpath = os.path.join(sys.path[0], '..')

class TestVTYBase(unittest.TestCase):

    def vty_command(self):
        raise Exception("Needs to be implemented by a subclass")

    def vty_app(self):
        raise Exception("Needs to be implemented by a subclass")

    def setUp(self):
        osmo_vty_cmd = self.vty_command()[:]
        config_index = osmo_vty_cmd.index('-c')
        if config_index:
            cfi = config_index + 1
            osmo_vty_cmd[cfi] = os.path.join(confpath, osmo_vty_cmd[cfi])

        try:
            self.proc = osmoutil.popen_devnull(osmo_vty_cmd)
        except OSError:
            print >> sys.stderr, "Current directory: %s" % os.getcwd()
            print >> sys.stderr, "Consider setting -b"

        appstring = self.vty_app()[2]
        appport = self.vty_app()[0]
        self.vty = obscvty.VTYInteract(appstring, "127.0.0.1", appport)

    def tearDown(self):
        if self.vty:
            self.vty._close_socket()
        self.vty = None
        osmoutil.end_proc(self.proc)


class TestSMPPMSC(TestVTYBase):

    def vty_command(self):
        return ["./src/osmo-msc/osmo-msc", "-c",
                "doc/examples/osmo-msc/osmo-msc.cfg"]

    def vty_app(self):
        return (4254, "./src/osmo-msc/osmo-msc", "OsmoMSC", "msc")

    def testSMPPCrashes(self):
        # Enable the configuration
        self.vty.enable()
        self.assertTrue(self.vty.verify("configure terminal", ['']))
        self.assertEquals(self.vty.node(), 'config')

        self.assertTrue(self.vty.verify('smpp', ['']))
        self.assertEquals(self.vty.node(), 'config-smpp')
        self.assertTrue(self.vty.verify('system-id test', ['']))
        self.assertTrue(self.vty.verify('local-tcp-port 2775', ['']))
        self.assertTrue(self.vty.verify('esme test', ['']))
        self.assertEquals(self.vty.node(), 'config-smpp-esme')
        self.assertTrue(self.vty.verify('default-route', ['']))
        self.assertTrue(self.vty.verify('end', ['']))

        # MSC should listen to 2775 now!
        sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sck.setblocking(1)
        sck.connect(('0.0.0.0', 2775))
        sck.sendall('\x00\x00\x00\x02\x00')
        sck.close()

        # Check if the VTY is still there
        self.vty.verify('disable',[''])

        # Now for the second packet
        sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sck.setblocking(1)
        sck.connect(('0.0.0.0', 2775))
        sck.sendall('\x00\x01\x00\x01\x01')
        sck.close()

        self.vty.verify('enable',[''])

if __name__ == '__main__':
    import argparse
    import sys

    workdir = '.'

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", dest="verbose",
                        action="store_true", help="verbose mode")
    parser.add_argument("-p", "--pythonconfpath", dest="p",
                        help="searchpath for config")
    parser.add_argument("-w", "--workdir", dest="w",
                        help="Working directory")
    args = parser.parse_args()

    verbose_level = 1
    if args.verbose:
        verbose_level = 2

    if args.w:
        workdir = args.w

    if args.p:
        confpath = args.p

    print "confpath %s, workdir %s" % (confpath, workdir)
    os.chdir(workdir)
    print "Running tests for specific SMPP"
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestSMPPMSC))
    res = unittest.TextTestRunner(verbosity=verbose_level).run(suite)
    sys.exit(len(res.errors) + len(res.failures))
