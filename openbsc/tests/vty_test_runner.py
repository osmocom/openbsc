#!/usr/bin/env python

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
import time
import unittest
import socket

import osmopy.obscvty as obscvty
import osmopy.osmoutil as osmoutil

confpath = '.'

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
            print "Launch: %s from %s" % (' '.join(osmo_vty_cmd), os.getcwd())
            self.proc = osmoutil.popen_devnull(osmo_vty_cmd)
        except OSError:
            print >> sys.stderr, "Current directory: %s" % os.getcwd()
            print >> sys.stderr, "Consider setting -b"
        time.sleep(1)

        appstring = self.vty_app()[2]
        appport = self.vty_app()[0]
        self.vty = obscvty.VTYInteract(appstring, "127.0.0.1", appport)

    def tearDown(self):
        self.vty = None
        osmoutil.end_proc(self.proc)

class TestVTYNITB(TestVTYBase):

    def vty_command(self):
        return ["./src/osmo-nitb/osmo-nitb", "-c",
                "doc/examples/osmo-nitb/nanobts/openbsc.cfg"]

    def vty_app(self):
        return (4242, "./src/osmo-nitb/osmo-nitb", "OpenBSC", "nitb")

    def testEnableDisablePeriodicLU(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("network")
        self.vty.command("bts 0")

        # Test invalid input
        self.vty.verify("periodic location update 0", ['% Unknown command.'])
        self.vty.verify("periodic location update 5", ['% Unknown command.'])
        self.vty.verify("periodic location update 1531", ['% Unknown command.'])

        # Enable periodic lu..
        self.vty.verify("periodic location update 60", [''])
        res = self.vty.command("write terminal")
        self.assert_(res.find('periodic location update 60') > 0)
        self.assertEquals(res.find('no periodic location update'), -1)

        # Now disable it..
        self.vty.verify("no periodic location update", [''])
        res = self.vty.command("write terminal")
        self.assertEquals(res.find('periodic location update 60'), -1)
        self.assert_(res.find('no periodic location update') > 0)

class TestVTYBSC(TestVTYBase):

    def vty_command(self):
        return ["./src/osmo-bsc/osmo-bsc", "-c",
                "doc/examples/osmo-bsc/osmo-bsc.cfg"]

    def vty_app(self):
        return (4242, "./src/osmo-bsc/osmo-bsc", "OsmoBSC", "bsc")

    def testUssdNotifications(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("msc")

        # Test invalid input
        self.vty.verify("bsc-msc-lost-text", ['% Command incomplete.'])

        # Enable USSD notifications
        self.vty.verify("bsc-msc-lost-text MSC disconnected", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assert_(res.find('bsc-msc-lost-text MSC disconnected') > 0)
        self.assertEquals(res.find('no bsc-msc-lost-text'), -1)

        # Now disable it..
        self.vty.verify("no bsc-msc-lost-text", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assertEquals(res.find('bsc-msc-lost-text MSC disconnected'), -1)
        self.assert_(res.find('no bsc-msc-lost-text') > 0)

class TestVTYNAT(TestVTYBase):

    def vty_command(self):
        return ["./src/osmo-bsc_nat/osmo-bsc_nat", "-c",
                "doc/examples/osmo-bsc_nat/osmo-bsc_nat.cfg"]

    def vty_app(self):
        return (4244, "src/osmo-bsc_nat/osmo-bsc_nat",  "OsmoBSCNAT", "nat")

    def testRewriteNoRewrite(self):
        self.vty.enable()
        res = self.vty.command("configure terminal")
        res = self.vty.command("nat")
        res = self.vty.command("number-rewrite rewrite.cfg")
        res = self.vty.command("no number-rewrite")

    def testRewritePostNoRewrite(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("nat")
        self.vty.verify("number-rewrite-post rewrite.cfg", [''])
        self.vty.verify("no number-rewrite-post", [''])


    def testPrefixTreeLoading(self):
        cfg = os.path.join(confpath, "tests/bsc-nat-trie/prefixes.csv")

        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("nat")
        res = self.vty.command("prefix-tree %s" % cfg)
        self.assertEqual(res, "% prefix-tree loaded 17 rules.")
        self.vty.command("end")

        res = self.vty.command("show prefix-tree")
        self.assertEqual(res, '1,1\r\n12,2\r\n123,3\r\n1234,4\r\n12345,5\r\n123456,6\r\n1234567,7\r\n12345678,8\r\n123456789,9\r\n1234567890,10\r\n13,11\r\n14,12\r\n15,13\r\n16,14\r\n82,16\r\n823455,15\r\n+49123,17')

        self.vty.command("configure terminal")
        self.vty.command("nat")
        self.vty.command("no prefix-tree")
        self.vty.command("end")

        res = self.vty.command("show prefix-tree")
        self.assertEqual(res, "% there is now prefix tree loaded.")

    def testUssdSideChannelProvider(self):
        self.vty.command("end")
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("nat")
        self.vty.command("ussd-token key")
        self.vty.command("end")

        res = self.vty.verify("show ussd-connection", ['The USSD side channel provider is not connected and not authorized.'])
        self.assertTrue(res)

        ussdSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ussdSocket.connect(('127.0.0.1', 5001))
        ussdSocket.settimeout(2.0)
        print "Connected to %s:%d" % ussdSocket.getpeername()

        print "Expecting ID_GET request"
        data = ussdSocket.recv(4)
        self.assertEqual(data, "\x00\x01\xfe\x04")

        print "Going to send ID_RESP response"
        res = ussdSocket.send("\x00\x07\xfe\x05\x00\x04\x01\x6b\x65\x79")
        self.assertEqual(res, 10)

        # initiating PING/PONG cycle to know, that the ID_RESP message has been processed

        print "Going to send PING request"
        res = ussdSocket.send("\x00\x01\xfe\x00")
        self.assertEqual(res, 4)

        print "Expecting PONG response"
        data = ussdSocket.recv(4)
        self.assertEqual(data, "\x00\x01\xfe\x01")

        res = self.vty.verify("show ussd-connection", ['The USSD side channel provider is connected and authorized.'])
        self.assertTrue(res)

        print "Going to shut down connection"
        ussdSocket.shutdown(socket.SHUT_WR)

        print "Expecting EOF"
        data = ussdSocket.recv(4)
        self.assertEqual(data, "")

        ussdSocket.close()

        res = self.vty.verify("show ussd-connection", ['The USSD side channel provider is not connected and not authorized.'])
        self.assertTrue(res)

def add_nat_test(suite, workdir):
    if not os.path.isfile(os.path.join(workdir, "src/osmo-bsc_nat/osmo-bsc_nat")):
        print("Skipping the NAT test")
        return
    test = unittest.TestLoader().loadTestsFromTestCase(TestVTYNAT)
    suite.addTest(test)

def add_bsc_test(suite, workdir):
    if not os.path.isfile(os.path.join(workdir, "src/osmo-bsc/osmo-bsc")):
        print("Skipping the BSC test")
        return
    test = unittest.TestLoader().loadTestsFromTestCase(TestVTYBSC)
    suite.addTest(test)

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
    print "Running tests for specific VTY commands"
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestVTYNITB))
    add_bsc_test(suite, workdir)
    add_nat_test(suite, workdir)
    res = unittest.TextTestRunner(verbosity=verbose_level).run(suite)
    sys.exit(len(res.errors) + len(res.failures))
