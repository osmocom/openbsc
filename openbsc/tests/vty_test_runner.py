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

class TestVTYMGCP(TestVTYBase):
    def vty_command(self):
        return ["./src/osmo-bsc_mgcp/osmo-bsc_mgcp", "-c",
                "doc/examples/osmo-bsc_mgcp/mgcp.cfg"]

    def vty_app(self):
        return (4243, "./src/osmo-bsc_mgcp/osmo-bsc_mgcp", "OpenBSC MGCP", "mgcp")

    def testForcePtime(self):
	self.vty.enable()
	res = self.vty.command("show running-config")
	self.assert_(res.find('  rtp force-ptime 20\r') > 0)
	self.assertEquals(res.find('  no rtp force-ptime\r'), -1)

	self.vty.command("configure terminal")
	self.vty.command("mgcp")
	self.vty.command("no rtp force-ptime")
	res = self.vty.command("show running-config")
	self.assertEquals(res.find('  rtp force-ptime 20\r'), -1)
	self.assertEquals(res.find('  no rtp force-ptime\r'), -1)


class TestVTYGenericBSC(TestVTYBase):

    def checkForEndAndExit(self):
        res = self.vty.command("list")
        #print ('looking for "exit"\n')
        self.assert_(res.find('  exit\r') > 0)
        #print 'found "exit"\nlooking for "end"\n'
        self.assert_(res.find('  end\r') > 0)
        #print 'found "end"\n'

    def _testConfigNetworkTree(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify("configure terminal",['']))
        self.assertEquals(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("network",['']))
        self.assertEquals(self.vty.node(), 'config-net')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("bts 0",['']))
        self.assertEquals(self.vty.node(), 'config-net-bts')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("trx 0",['']))
        self.assertEquals(self.vty.node(), 'config-net-bts-trx')
        self.checkForEndAndExit()
        self.vty.command("write terminal")
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertEquals(self.vty.node(), 'config-net-bts')
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertTrue(self.vty.verify("bts 1",['']))
        self.assertEquals(self.vty.node(), 'config-net-bts')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("trx 1",['']))
        self.assertEquals(self.vty.node(), 'config-net-bts-trx')
        self.checkForEndAndExit()
        self.vty.command("write terminal")
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertEquals(self.vty.node(), 'config-net-bts')
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertEquals(self.vty.node(), 'config-net')
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertTrue(self.vty.node() is None)

class TestVTYNITB(TestVTYGenericBSC):

    def vty_command(self):
        return ["./src/osmo-nitb/osmo-nitb", "-c",
                "doc/examples/osmo-nitb/nanobts/openbsc.cfg"]

    def vty_app(self):
        return (4242, "./src/osmo-nitb/osmo-nitb", "OpenBSC", "nitb")

    def testConfigNetworkTree(self):
        self._testConfigNetworkTree()

    def checkForSmpp(self):
        """SMPP is not always enabled, check if it is"""
        res = self.vty.command("list")
        return "smpp" in res

    def testVtyTree(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify("configure terminal", ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('mncc-int', ['']))
        self.assertEquals(self.vty.node(), 'config-mncc-int')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))

        if self.checkForSmpp():
            self.assertEquals(self.vty.node(), 'config')
            self.assertTrue(self.vty.verify('smpp', ['']))
            self.assertEquals(self.vty.node(), 'config-smpp')
            self.checkForEndAndExit()
            self.assertTrue(self.vty.verify("exit", ['']))

        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify("exit", ['']))
        self.assertTrue(self.vty.node() is None)

        # Check searching for outer node's commands
        self.vty.command("configure terminal")
        self.vty.command('mncc-int')

        if self.checkForSmpp():
            self.vty.command('smpp')
            self.assertEquals(self.vty.node(), 'config-smpp')
            self.vty.command('mncc-int')

        self.assertEquals(self.vty.node(), 'config-mncc-int')

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

    def testEnableDisableSiHacks(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("network")
        self.vty.command("bts 0")

        # Enable periodic lu..
        self.vty.verify("force-combined-si", [''])
        res = self.vty.command("write terminal")
        self.assert_(res.find('  force-combined-si') > 0)
        self.assertEquals(res.find('no force-combined-si'), -1)

        # Now disable it..
        self.vty.verify("no force-combined-si", [''])
        res = self.vty.command("write terminal")
        self.assertEquals(res.find('  force-combined-si'), -1)
        self.assert_(res.find('no force-combined-si') > 0)

    def testRachAccessControlClass(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("network")
        self.vty.command("bts 0")

        # Test invalid input
        self.vty.verify("rach access-control-class", ['% Command incomplete.'])
        self.vty.verify("rach access-control-class 1", ['% Command incomplete.'])
        self.vty.verify("rach access-control-class -1", ['% Unknown command.'])
        self.vty.verify("rach access-control-class 10", ['% Unknown command.'])
        self.vty.verify("rach access-control-class 16", ['% Unknown command.'])

        # Barred rach access control classes
        for classNum in range(16):
            if classNum != 10:
                self.vty.verify("rach access-control-class " + str(classNum) + " barred", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        for classNum in range(16):
            if classNum != 10:
                self.assert_(res.find("rach access-control-class " + str(classNum) + " barred") > 0)

        # Allowed rach access control classes
        for classNum in range(16):
            if classNum != 10:
                self.vty.verify("rach access-control-class " + str(classNum) + " allowed", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        for classNum in range(16):
            if classNum != 10:
                self.assertEquals(res.find("rach access-control-class " + str(classNum) + " barred"), -1)

    def testSubscriberCreate(self):
        self.vty.enable()

        imsi = "204300854013739"

        # Initially we don't have this subscriber
        self.vty.verify('show subscriber imsi '+imsi, ['% No subscriber found for imsi '+imsi])

        # Lets create one
        res = self.vty.command('subscriber create imsi '+imsi)
        self.assert_(res.find("    IMSI: "+imsi) > 0)

        # Now we have it
        res = self.vty.command('show subscriber imsi '+imsi)
        self.assert_(res.find("    IMSI: "+imsi) > 0)

    def testShowPagingGroup(self):
        res = self.vty.command("show paging-group 255 1234567")
        self.assertEqual(res, "% can't find BTS 255")
        res = self.vty.command("show paging-group 0 1234567")
        self.assertEquals(res, "%Paging group for IMSI 1234567 on BTS #0 is 7")

    def testShowNetwork(self):
        res = self.vty.command("show network")
        self.assert_(res.startswith('BSC is on Country Code') >= 0)

class TestVTYBSC(TestVTYGenericBSC):

    def vty_command(self):
        return ["./src/osmo-bsc/osmo-bsc", "-c",
                "doc/examples/osmo-bsc/osmo-bsc.cfg"]

    def vty_app(self):
        return (4242, "./src/osmo-bsc/osmo-bsc", "OsmoBSC", "bsc")

    def testConfigNetworkTree(self):
        self._testConfigNetworkTree()

    def testVtyTree(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify("configure terminal", ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("msc 0", ['']))
        self.assertEquals(self.vty.node(), 'config-msc')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("exit", ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify("bsc", ['']))
        self.assertEquals(self.vty.node(), 'config-bsc')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("exit", ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify("exit", ['']))
        self.assertTrue(self.vty.node() is None)

        # Check searching for outer node's commands
        self.vty.command("configure terminal")
        self.vty.command('msc 0')
        self.vty.command("bsc")
        self.assertEquals(self.vty.node(), 'config-bsc')
        self.vty.command("msc 0")
        self.assertEquals(self.vty.node(), 'config-msc')

    def testUssdNotificationsMsc(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("msc")

        # Test invalid input
        self.vty.verify("bsc-msc-lost-text", ['% Command incomplete.'])
        self.vty.verify("bsc-welcome-text", ['% Command incomplete.'])
        self.vty.verify("bsc-grace-text", ['% Command incomplete.'])

        # Enable USSD notifications
        self.vty.verify("bsc-msc-lost-text MSC disconnected", [''])
        self.vty.verify("bsc-welcome-text Hello MS", [''])
        self.vty.verify("bsc-grace-text In grace period", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assert_(res.find('bsc-msc-lost-text MSC disconnected') > 0)
        self.assertEquals(res.find('no bsc-msc-lost-text'), -1)
        self.assert_(res.find('bsc-welcome-text Hello MS') > 0)
        self.assertEquals(res.find('no bsc-welcome-text'), -1)
        self.assert_(res.find('bsc-grace-text In grace period') > 0)
        self.assertEquals(res.find('no bsc-grace-text'), -1)

        # Now disable it..
        self.vty.verify("no bsc-msc-lost-text", [''])
        self.vty.verify("no bsc-welcome-text", [''])
        self.vty.verify("no bsc-grace-text", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assertEquals(res.find('bsc-msc-lost-text MSC disconnected'), -1)
        self.assert_(res.find('no bsc-msc-lost-text') > 0)
        self.assertEquals(res.find('bsc-welcome-text Hello MS'), -1)
        self.assert_(res.find('no bsc-welcome-text') > 0)
        self.assertEquals(res.find('bsc-grace-text In grace period'), -1)
        self.assert_(res.find('no bsc-grace-text') > 0)

    def testUssdNotificationsBsc(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("bsc")

        # Test invalid input
        self.vty.verify("missing-msc-text", ['% Command incomplete.'])

        # Enable USSD notifications
        self.vty.verify("missing-msc-text No MSC found", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assert_(res.find('missing-msc-text No MSC found') > 0)
        self.assertEquals(res.find('no missing-msc-text'), -1)

        # Now disable it..
        self.vty.verify("no missing-msc-text", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assertEquals(res.find('missing-msc-text No MSC found'), -1)
        self.assert_(res.find('no missing-msc-text') > 0)

    def testNetworkTimezone(self):
        self.vty.enable()
        self.vty.verify("configure terminal", [''])
        self.vty.verify("network", [''])
        self.vty.verify("bts 0", [''])

        # Test invalid input
        self.vty.verify("timezone", ['% Command incomplete.'])
        self.vty.verify("timezone 20 0", ['% Unknown command.'])
        self.vty.verify("timezone 0 11", ['% Unknown command.'])
        self.vty.verify("timezone 0 0 99", ['% Unknown command.'])

        # Set time zone without DST
        self.vty.verify("timezone 2 30", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assert_(res.find('timezone 2 30') > 0)
        self.assertEquals(res.find('timezone 2 30 '), -1)

        # Set time zone with DST
        self.vty.verify("timezone 2 30 1", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assert_(res.find('timezone 2 30 1') > 0)

        # Now disable it..
        self.vty.verify("no timezone", [''])

        # Verify settings
        res = self.vty.command("write terminal")
        self.assertEquals(res.find(' timezone'), -1)

    def testShowNetwork(self):
        res = self.vty.command("show network")
        self.assert_(res.startswith('BSC is on Country Code') >= 0)

class TestVTYNAT(TestVTYGenericBSC):

    def vty_command(self):
        return ["./src/osmo-bsc_nat/osmo-bsc_nat", "-c",
                "doc/examples/osmo-bsc_nat/osmo-bsc_nat.cfg"]

    def vty_app(self):
        return (4244, "src/osmo-bsc_nat/osmo-bsc_nat",  "OsmoBSCNAT", "nat")

    def testVtyTree(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('mgcp', ['']))
        self.assertEquals(self.vty.node(), 'config-mgcp')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('nat', ['']))
        self.assertEquals(self.vty.node(), 'config-nat')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('bsc 0', ['']))
        self.assertEquals(self.vty.node(), 'config-nat-bsc')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEquals(self.vty.node(), 'config-nat')
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertTrue(self.vty.node() is None)

        # Check searching for outer node's commands
        self.vty.command('configure terminal')
        self.vty.command('mgcp')
        self.vty.command('nat')
        self.assertEquals(self.vty.node(), 'config-nat')
        self.vty.command('mgcp')
        self.assertEquals(self.vty.node(), 'config-mgcp')
        self.vty.command('nat')
        self.assertEquals(self.vty.node(), 'config-nat')
        self.vty.command('bsc 0')
        self.vty.command('mgcp')
        self.assertEquals(self.vty.node(), 'config-mgcp')

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

    def testAccessList(self):
        """
        Verify that the imsi-deny can have a reject cause or no reject cause
        """
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("nat")

        # Old default
        self.vty.command("access-list test-default imsi-deny ^123[0-9]*$")
        res = self.vty.command("show running-config").split("\r\n")
        asserted = False
        for line in res:
           if line.startswith(" access-list test-default"):
                self.assertEqual(line, " access-list test-default imsi-deny ^123[0-9]*$ 11 11")
                asserted = True
        self.assert_(asserted)

        # Check the optional CM Service Reject Cause
        self.vty.command("access-list test-cm-deny imsi-deny ^123[0-9]*$ 42").split("\r\n")
        res = self.vty.command("show running-config").split("\r\n")
        asserted = False
        for line in res:
           if line.startswith(" access-list test-cm"):
                self.assertEqual(line, " access-list test-cm-deny imsi-deny ^123[0-9]*$ 42 11")
                asserted = True
        self.assert_(asserted)

        # Check the optional LU Reject Cause
        self.vty.command("access-list test-lu-deny imsi-deny ^123[0-9]*$ 23 42").split("\r\n")
        res = self.vty.command("show running-config").split("\r\n")
        asserted = False
        for line in res:
           if line.startswith(" access-list test-lu"):
                self.assertEqual(line, " access-list test-lu-deny imsi-deny ^123[0-9]*$ 23 42")
                asserted = True
        self.assert_(asserted)

class TestVTYGbproxy(TestVTYGenericBSC):

    def vty_command(self):
        return ["./src/gprs/osmo-gbproxy", "-c",
                "doc/examples/osmo-gbproxy/osmo-gbproxy.cfg"]

    def vty_app(self):
        return (4246, "./src/gprs/osmo-gbproxy", "OsmoGbProxy", "bsc")

    def testVtyTree(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('ns', ['']))
        self.assertEquals(self.vty.node(), 'config-ns')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('gbproxy', ['']))
        self.assertEquals(self.vty.node(), 'config-gbproxy')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEquals(self.vty.node(), 'config')

    def testVtyShow(self):
        res = self.vty.command("show ns")
        self.assert_(res.find('Encapsulation NS-UDP-IP') >= 0)

        res = self.vty.command("show gbproxy stats")
        self.assert_(res.find('GBProxy Global Statistics') >= 0)

    def testVtyDeletePeer(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('delete-gbproxy-peer 9999 bvci 7777', ['BVC not found']))
        res = self.vty.command("delete-gbproxy-peer 9999 all dry-run")
        self.assert_(res.find('Not Deleted 0 BVC') >= 0)
        self.assert_(res.find('Not Deleted 0 NS-VC') >= 0)
        res = self.vty.command("delete-gbproxy-peer 9999 only-bvc dry-run")
        self.assert_(res.find('Not Deleted 0 BVC') >= 0)
        self.assert_(res.find('Not Deleted 0 NS-VC') < 0)
        res = self.vty.command("delete-gbproxy-peer 9999 only-nsvc dry-run")
        self.assert_(res.find('Not Deleted 0 BVC') < 0)
        self.assert_(res.find('Not Deleted 0 NS-VC') >= 0)
        res = self.vty.command("delete-gbproxy-peer 9999 all")
        self.assert_(res.find('Deleted 0 BVC') >= 0)
        self.assert_(res.find('Deleted 0 NS-VC') >= 0)

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

def add_gbproxy_test(suite, workdir):
    if not os.path.isfile(os.path.join(workdir, "src/gprs/osmo-gbproxy")):
        print("Skipping the Gb-Proxy test")
        return
    test = unittest.TestLoader().loadTestsFromTestCase(TestVTYGbproxy)
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
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestVTYMGCP))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestVTYNITB))
    add_bsc_test(suite, workdir)
    add_nat_test(suite, workdir)
    add_gbproxy_test(suite, workdir)
    res = unittest.TextTestRunner(verbosity=verbose_level).run(suite)
    sys.exit(len(res.errors) + len(res.failures))
