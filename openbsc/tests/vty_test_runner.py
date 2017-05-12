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

import os, sys
import time
import unittest
import socket
import subprocess

import osmopy.obscvty as obscvty
import osmopy.osmoutil as osmoutil

# add $top_srcdir/contrib to find ipa.py
sys.path.append(os.path.join(sys.path[0], '..', 'contrib'))

from ipa import IPA

# to be able to find $top_srcdir/doc/...
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

    def testOmitAudio(self):
        self.vty.enable()
        res = self.vty.command("show running-config")
        self.assert_(res.find('  sdp audio-payload send-name\r') > 0)
        self.assertEquals(res.find('  no sdp audio-payload send-name\r'), -1)

        self.vty.command("configure terminal")
        self.vty.command("mgcp")
        self.vty.command("no sdp audio-payload send-name")
        res = self.vty.command("show running-config")
        self.assertEquals(res.find('  rtp sdp audio-payload send-name\r'), -1)
        self.assert_(res.find('  no sdp audio-payload send-name\r') > 0)

        # TODO: test it for the trunk!

    def testBindAddr(self):
        self.vty.enable()

        self.vty.command("configure terminal")
        self.vty.command("mgcp")

        # enable.. disable bts-bind-ip
        self.vty.command("rtp bts-bind-ip 254.253.252.250")
        res = self.vty.command("show running-config")
        self.assert_(res.find('rtp bts-bind-ip 254.253.252.250') > 0)
        self.vty.command("no rtp bts-bind-ip")
        res = self.vty.command("show running-config")
        self.assertEquals(res.find('  rtp bts-bind-ip'), -1)

        # enable.. disable net-bind-ip
        self.vty.command("rtp net-bind-ip 254.253.252.250")
        res = self.vty.command("show running-config")
        self.assert_(res.find('rtp net-bind-ip 254.253.252.250') > 0)
        self.vty.command("no rtp net-bind-ip")
        res = self.vty.command("show running-config")
        self.assertEquals(res.find('  rtp net-bind-ip'), -1)


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

    def testSmppFirst(self):
        # enable the configuration
        self.vty.enable()
        self.vty.command("configure terminal")

        if not self.checkForSmpp():
            return

        self.vty.command("smpp")

        # check the default
        res = self.vty.command("write terminal")
        self.assert_(res.find(' no smpp-first') > 0)

        self.vty.verify("smpp-first", [''])
        res = self.vty.command("write terminal")
        self.assert_(res.find(' smpp-first') > 0)
        self.assertEquals(res.find('no smpp-first'), -1)

        self.vty.verify("no smpp-first", [''])
        res = self.vty.command("write terminal")
        self.assert_(res.find('no smpp-first') > 0)

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

    def testVtyAuthorization(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("network")
        self.assertTrue(self.vty.verify("auth policy closed", ['']))
        self.assertTrue(self.vty.verify("auth policy regexp", ['']))
        self.assertTrue(self.vty.verify("authorized-regexp ^001", ['']))
        self.assertTrue(self.vty.verify("authorized-regexp 02$", ['']))
        self.assertTrue(self.vty.verify("authorized-regexp *123.*", ['']))
        self.vty.command("end")
        self.vty.command("configure terminal")
        self.vty.command("nitb")
        self.assertTrue(self.vty.verify("subscriber-create-on-demand", ['']))
        self.assertTrue(self.vty.verify("subscriber-create-on-demand no-extension", ['']))
        self.vty.command("end")

    def testSi2Q(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("network")
        self.vty.command("bts 0")
        before = self.vty.command("show running-config")
        self.vty.command("si2quater neighbor-list add earfcn 1911 threshold 11 2")
        self.vty.command("si2quater neighbor-list add earfcn 1924 threshold 11 3")
        self.vty.command("si2quater neighbor-list add earfcn 2111 threshold 11")
        self.vty.command("si2quater neighbor-list del earfcn 1911")
        self.vty.command("si2quater neighbor-list del earfcn 1924")
        self.vty.command("si2quater neighbor-list del earfcn 2111")
        self.assertEquals(before, self.vty.command("show running-config"))
        self.vty.command("si2quater neighbor-list add uarfcn 1976 13 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 38 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 44 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 120 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 140 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 163 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 166 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 217 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 224 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 225 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 226 1")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 13")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 38")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 44")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 120")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 140")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 163")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 166")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 217")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 224")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 225")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 226")
        self.assertEquals(before, self.vty.command("show running-config"))

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

    def testSubscriberCreateDeleteTwice(self):
        """
        OS#1657 indicates that there might be an issue creating the
        same subscriber twice. This test will use the VTY command to
        create a subscriber and then issue a second create command
        with the same IMSI. The test passes if the VTY continues to
        respond to VTY commands.
        """
        self.vty.enable()

        imsi = "204300854013739"

        # Initially we don't have this subscriber
        self.vty.verify('show subscriber imsi '+imsi, ['% No subscriber found for imsi '+imsi])

        # Lets create one
        res = self.vty.command('subscriber create imsi '+imsi)
        self.assert_(res.find("    IMSI: "+imsi) > 0)
        # And now create one again.
        res2 = self.vty.command('subscriber create imsi '+imsi)
        self.assert_(res2.find("    IMSI: "+imsi) > 0)
        self.assertEqual(res, res2)

        # Verify it has been created
        res = self.vty.command('show subscriber imsi '+imsi)
        self.assert_(res.find("    IMSI: "+imsi) > 0)

        # Delete it
        res = self.vty.command('subscriber imsi ' + imsi + ' delete')
        self.assert_("" == res)

        # Now it should not be there anymore
        res = self.vty.command('show subscriber imsi '+imsi)
        self.assert_(('% No subscriber found for imsi ' + imsi) == res)


    def testSubscriberCreateDelete(self):
        self.vty.enable()

        imsi = "204300854013739"
        imsi2 = "222301824913762"
        imsi3 = "333500854113763"
        imsi4 = "444583744053764"

        # Initially we don't have this subscriber
        self.vty.verify('show subscriber imsi '+imsi, ['% No subscriber found for imsi '+imsi])

        # Lets create one
        res = self.vty.command('subscriber create imsi '+imsi)
        self.assert_(res.find("    IMSI: "+imsi) > 0)
        self.assert_(res.find("Extension") > 0)

        # Now we have it
        res = self.vty.command('show subscriber imsi '+imsi)
        self.assert_(res.find("    IMSI: "+imsi) > 0)

        # With narrow random interval
        self.vty.command("configure terminal")
        self.vty.command("nitb")
        self.assertTrue(self.vty.verify("subscriber-create-on-demand", ['']))
        # wrong interval
        res = self.vty.command("subscriber-create-on-demand random 221 122")
        # error string will contain arguments
        self.assert_(res.find("122") > 0)
        self.assert_(res.find("221") > 0)
        # correct interval - silent ok
        self.assertTrue(self.vty.verify("subscriber-create-on-demand random 221 222", ['']))
        self.vty.command("end")

        res = self.vty.command('subscriber create imsi ' + imsi2)
        self.assert_(res.find("    IMSI: " + imsi2) > 0)
        self.assert_(res.find("221") > 0 or res.find("222") > 0)
        self.assert_(res.find("    Extension: ") > 0)

        # Without extension
        self.vty.command("configure terminal")
        self.vty.command("nitb")
        self.assertTrue(self.vty.verify("subscriber-create-on-demand no-extension", ['']))
        self.vty.command("end")
        res = self.vty.command('subscriber create imsi ' + imsi3)
        self.assert_(res.find("    IMSI: " + imsi3) > 0)
        self.assertEquals(res.find("Extension"), -1)

        # With extension again
        self.vty.command("configure terminal")
        self.vty.command("nitb")
        self.assertTrue(self.vty.verify("no subscriber-create-on-demand", ['']))
        self.assertTrue(self.vty.verify("subscriber-create-on-demand", ['']))
        self.assertTrue(self.vty.verify("subscriber-create-on-demand random 221 666", ['']))
        self.vty.command("end")

        res = self.vty.command('subscriber create imsi ' + imsi4)
        self.assert_(res.find("    IMSI: " + imsi4) > 0)
        self.assert_(res.find("    Extension: ") > 0)

        # Delete it
        res = self.vty.command('subscriber imsi ' + imsi + ' delete')
        self.assert_("" == res)
        res = self.vty.command('subscriber imsi ' + imsi2 + ' delete')
        self.assert_("" == res)
        res = self.vty.command('subscriber imsi ' + imsi3 + ' delete')
        self.assert_("" == res)
        res = self.vty.command('subscriber imsi ' + imsi4 + ' delete')
        self.assert_("" == res)

        # Now it should not be there anymore
        res = self.vty.command('show subscriber imsi '+imsi)
        self.assert_(('% No subscriber found for imsi ' + imsi) == res)

        # range
        self.vty.command("end")
        self.vty.command("configure terminal")
        self.vty.command("nitb")
        self.assertTrue(self.vty.verify("subscriber-create-on-demand random 9999999998 9999999999", ['']))
        res = self.vty.command("show running-config")
        self.assert_(res.find("subscriber-create-on-demand random 9999999998 9999999999"))
        self.vty.command("end")

        res = self.vty.command('subscriber create imsi ' + imsi)
        print(res)
        self.assert_(res.find("    IMSI: " + imsi) > 0)
        self.assert_(res.find("9999999998") > 0 or res.find("9999999999") > 0)
        self.assert_(res.find("    Extension: ") > 0)

        res = self.vty.command('subscriber imsi ' + imsi + ' delete')
        self.assert_("" == res)

        res = self.vty.command('show subscriber imsi '+imsi)
        self.assert_(('% No subscriber found for imsi ' + imsi) == res)


    def testSubscriberSettings(self):
        self.vty.enable()

        imsi = "204300854013739"
        imsi2 = "204301824913769"
        wrong_imsi = "204300999999999"

        # Lets create one
        res = self.vty.command('subscriber create imsi '+imsi)
        self.assert_(res.find("    IMSI: "+imsi) > 0)
        self.assert_(res.find("Extension") > 0)

        self.vty.verify('subscriber imsi '+wrong_imsi+' name wrong', ['% No subscriber found for imsi '+wrong_imsi])
        res = self.vty.command('subscriber imsi '+imsi+' name '+('X' * 160))
        self.assert_(res.find("NAME is too long") > 0)

        self.vty.verify('subscriber imsi '+imsi+' name '+('G' * 159), [''])

        self.vty.verify('subscriber imsi '+wrong_imsi+' extension 840', ['% No subscriber found for imsi '+wrong_imsi])
        res = self.vty.command('subscriber imsi '+imsi+' extension '+('9' * 15))
        self.assert_(res.find("EXTENSION is too long") > 0)

        self.vty.verify('subscriber imsi '+imsi+' extension '+('1' * 14), [''])

        # With narrow random interval
        self.vty.command("configure terminal")
        self.vty.command("nitb")
        self.assertTrue(self.vty.verify("subscriber-create-on-demand", ['']))
        # wrong interval
        res = self.vty.command("subscriber-create-on-demand random 221 122")
        self.assert_(res.find("122") > 0)
        self.assert_(res.find("221") > 0)
        # correct interval
        self.assertTrue(self.vty.verify("subscriber-create-on-demand random 221 222", ['']))
        self.vty.command("end")

        # create subscriber with extension in a configured interval
        res = self.vty.command('subscriber create imsi ' + imsi2)
        self.assert_(res.find("    IMSI: " + imsi2) > 0)
        self.assert_(res.find("221") > 0 or res.find("222") > 0)
        self.assert_(res.find("    Extension: ") > 0)

        # Delete it
        res = self.vty.command('subscriber imsi ' + imsi + ' delete')
        self.assert_(res != "")
        # imsi2 is inactive so deletion should succeed
        res = self.vty.command('subscriber imsi ' + imsi2 + ' delete')
        self.assert_("" == res)

    def testShowPagingGroup(self):
        res = self.vty.command("show paging-group 255 1234567")
        self.assertEqual(res, "% can't find BTS 255")
        res = self.vty.command("show paging-group 0 1234567")
        self.assertEquals(res, "%Paging group for IMSI 1234567 on BTS #0 is 7")

    def testShowNetwork(self):
        res = self.vty.command("show network")
        self.assert_(res.startswith('BSC is on Country Code') >= 0)

    def testMeasurementFeed(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("mncc-int")

        res = self.vty.command("write terminal")
        self.assertEquals(res.find('meas-feed scenario'), -1)

        self.vty.command("meas-feed scenario bla")
        res = self.vty.command("write terminal")
        self.assert_(res.find('meas-feed scenario bla') > 0)

        self.vty.command("meas-feed scenario abcdefghijklmnopqrstuvwxyz01234567890")
        res = self.vty.command("write terminal")
        self.assertEquals(res.find('meas-feed scenario abcdefghijklmnopqrstuvwxyz01234567890'), -1)
        self.assertEquals(res.find('meas-feed scenario abcdefghijklmnopqrstuvwxyz012345'), -1)
        self.assert_(res.find('meas-feed scenario abcdefghijklmnopqrstuvwxyz01234') > 0)


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

    def testPingPongConfiguration(self):
        self.vty.enable()
        self.vty.verify("configure terminal", [''])
        self.vty.verify("network", [''])
        self.vty.verify("msc 0", [''])

        self.vty.verify("timeout-ping 12", [''])
        self.vty.verify("timeout-pong 14", [''])
        res = self.vty.command("show running-config")
        self.assert_(res.find(" timeout-ping 12") > 0)
        self.assert_(res.find(" timeout-pong 14") > 0)
        self.assert_(res.find(" no timeout-ping advanced") > 0)

        self.vty.verify("timeout-ping advanced", [''])
        res = self.vty.command("show running-config")
        self.assert_(res.find(" timeout-ping 12") > 0)
        self.assert_(res.find(" timeout-pong 14") > 0)
        self.assert_(res.find(" timeout-ping advanced") > 0)

        self.vty.verify("no timeout-ping advanced", [''])
        res = self.vty.command("show running-config")
        self.assert_(res.find(" timeout-ping 12") > 0)
        self.assert_(res.find(" timeout-pong 14") > 0)
        self.assert_(res.find(" no timeout-ping advanced") > 0)

        self.vty.verify("no timeout-ping", [''])
        res = self.vty.command("show running-config")
        self.assertEquals(res.find(" timeout-ping 12"), -1)
        self.assertEquals(res.find(" timeout-pong 14"), -1)
        self.assertEquals(res.find(" no timeout-ping advanced"), -1)
        self.assert_(res.find(" no timeout-ping") > 0)

        self.vty.verify("timeout-ping advanced", ['%ping handling is disabled. Enable it first.'])

        # And back to enabling it
        self.vty.verify("timeout-ping 12", [''])
        self.vty.verify("timeout-pong 14", [''])
        res = self.vty.command("show running-config")
        self.assert_(res.find(" timeout-ping 12") > 0)
        self.assert_(res.find(" timeout-pong 14") > 0)
        self.assert_(res.find(" timeout-ping advanced") > 0)

    def testMscDataCoreLACCI(self):
        self.vty.enable()
        res = self.vty.command("show running-config")
        self.assertEquals(res.find("core-location-area-code"), -1)
        self.assertEquals(res.find("core-cell-identity"), -1)

        self.vty.command("configure terminal")
        self.vty.command("msc 0")
        self.vty.command("core-location-area-code 666")
        self.vty.command("core-cell-identity 333")

        res = self.vty.command("show running-config")
        self.assert_(res.find("core-location-area-code 666") > 0)
        self.assert_(res.find("core-cell-identity 333") > 0)

class TestVTYNAT(TestVTYGenericBSC):

    def vty_command(self):
        return ["./src/osmo-bsc_nat/osmo-bsc_nat", "-l", "127.0.0.1", "-c",
                "doc/examples/osmo-bsc_nat/osmo-bsc_nat.cfg"]

    def vty_app(self):
        return (4244, "src/osmo-bsc_nat/osmo-bsc_nat",  "OsmoBSCNAT", "nat")

    def testBSCreload(self):
        # Use different port for the mock msc to avoid clashing with
        # the osmo-bsc_nat itself
        ip = "127.0.0.1"
        port = 5522
        self.vty.enable()
        bscs1 = self.vty.command("show bscs-config")
        nat_bsc_reload(self)
        bscs2 = self.vty.command("show bscs-config")
        # check that multiple calls to bscs-config-file give the same result
        self.assertEquals(bscs1, bscs2)

        # add new bsc
        self.vty.command("configure terminal")
        self.vty.command("nat")
        self.vty.command("bsc 5")
        self.vty.command("token key")
        self.vty.command("location_area_code 666")
        self.vty.command("end")

        # update bsc token
        self.vty.command("configure terminal")
        self.vty.command("nat")
        self.vty.command("bsc 1")
        self.vty.command("token xyu")
        self.vty.command("end")

        nat_msc_ip(self, ip, port)
        msc_socket, msc = nat_msc_test(self, ip, port, verbose=True)
        try:
            b0 = nat_bsc_sock_test(0, "lol", verbose=True, proc=self.proc)
            b1 = nat_bsc_sock_test(1, "xyu", verbose=True, proc=self.proc)
            b2 = nat_bsc_sock_test(5, "key", verbose=True, proc=self.proc)

            self.assertEquals("3 BSCs configured", self.vty.command("show nat num-bscs-configured"))
            self.assertTrue(3 == nat_bsc_num_con(self))
            self.assertEquals("MSC is connected: 1", self.vty.command("show msc connection"))

            nat_bsc_reload(self)
            bscs2 = self.vty.command("show bscs-config")
            # check that the reset to initial config succeeded
            self.assertEquals(bscs1, bscs2)

            self.assertEquals("2 BSCs configured", self.vty.command("show nat num-bscs-configured"))
            self.assertTrue(1 == nat_bsc_num_con(self))
            rem = self.vty.command("show bsc connections").split(' ')
            # remaining connection is for BSC0
            self.assertEquals('0', rem[2])
            # remaining connection is authorized
            self.assertEquals('1', rem[4])
            self.assertEquals("MSC is connected: 1", self.vty.command("show msc connection"))
        finally:
            msc.close()
            msc_socket.close()

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

    def testEnsureNoEnsureModeSet(self):
        self.vty.enable()
        res = self.vty.command("configure terminal")
        res = self.vty.command("nat")

        # Ensure the default
        res = self.vty.command("show running-config")
        self.assert_(res.find('\n sdp-ensure-amr-mode-set') > 0)

        self.vty.command("sdp-ensure-amr-mode-set")
        res = self.vty.command("show running-config")
        self.assert_(res.find('\n sdp-ensure-amr-mode-set') > 0)

        self.vty.command("no sdp-ensure-amr-mode-set")
        res = self.vty.command("show running-config")
        self.assert_(res.find('\n no sdp-ensure-amr-mode-set') > 0)

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
        res = ussdSocket.send(IPA().id_resp(IPA().tag_name('key')))
        self.assertEqual(res, 10)

        # initiating PING/PONG cycle to know, that the ID_RESP message has been processed

        print "Going to send PING request"
        res = ussdSocket.send(IPA().ping())
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

class TestVTYSGSN(TestVTYGenericBSC):

    def vty_command(self):
        return ["./src/gprs/osmo-sgsn", "-c",
                "doc/examples/osmo-sgsn/osmo-sgsn.cfg"]

    def vty_app(self):
        return (4245, "./src/gprs/osmo-sgsn", "OsmoSGSN", "sgsn")

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
        self.assertTrue(self.vty.verify('sgsn', ['']))
        self.assertEquals(self.vty.node(), 'config-sgsn')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEquals(self.vty.node(), 'config')

    def testVtyShow(self):
        res = self.vty.command("show ns")
        self.assert_(res.find('Encapsulation NS-UDP-IP') >= 0)
        self.assertTrue(self.vty.verify('show bssgp', ['']))
        self.assertTrue(self.vty.verify('show bssgp stats', ['']))
        # TODO: uncomment when the command does not segfault anymore
        # self.assertTrue(self.vty.verify('show bssgp nsei 123', ['']))
        # self.assertTrue(self.vty.verify('show bssgp nsei 123 stats', ['']))

        self.assertTrue(self.vty.verify('show sgsn', ['']))
        self.assertTrue(self.vty.verify('show mm-context all', ['']))
        self.assertTrue(self.vty.verify('show mm-context imsi 000001234567', ['No MM context for IMSI 000001234567']))
        self.assertTrue(self.vty.verify('show pdp-context all', ['']))

        res = self.vty.command("show sndcp")
        self.assert_(res.find('State of SNDCP Entities') >= 0)

        res = self.vty.command("show llc")
        self.assert_(res.find('State of LLC Entities') >= 0)

    def testVtyAuth(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('sgsn', ['']))
        self.assertEquals(self.vty.node(), 'config-sgsn')
        self.assertTrue(self.vty.verify('auth-policy accept-all', ['']))
        res = self.vty.command("show running-config")
        self.assert_(res.find('auth-policy accept-all') > 0)
        self.assertTrue(self.vty.verify('auth-policy acl-only', ['']))
        res = self.vty.command("show running-config")
        self.assert_(res.find('auth-policy acl-only') > 0)
        self.assertTrue(self.vty.verify('auth-policy closed', ['']))
        res = self.vty.command("show running-config")
        self.assert_(res.find('auth-policy closed') > 0)
        self.assertTrue(self.vty.verify('gsup remote-ip 127.0.0.4', ['']))
        self.assertTrue(self.vty.verify('gsup remote-port 2222', ['']))
        self.assertTrue(self.vty.verify('auth-policy remote', ['']))
        res = self.vty.command("show running-config")
        self.assert_(res.find('auth-policy remote') > 0)

    def testVtySubscriber(self):
        self.vty.enable()
        res = self.vty.command('show subscriber cache')
        self.assert_(res.find('1234567890') < 0)
        self.assertTrue(self.vty.verify('update-subscriber imsi 1234567890 create', ['']))
        res = self.vty.command('show subscriber cache')
        self.assert_(res.find('1234567890') >= 0)
        self.assert_(res.find('Authorized: 0') >= 0)
        self.assertTrue(self.vty.verify('update-subscriber imsi 1234567890 update-location-result ok', ['']))
        res = self.vty.command('show subscriber cache')
        self.assert_(res.find('1234567890') >= 0)
        self.assert_(res.find('Authorized: 1') >= 0)
        self.assertTrue(self.vty.verify('update-subscriber imsi 1234567890 cancel update-procedure', ['']))
        res = self.vty.command('show subscriber cache')
        self.assert_(res.find('1234567890') >= 0)
        self.assertTrue(self.vty.verify('update-subscriber imsi 1234567890 destroy', ['']))
        res = self.vty.command('show subscriber cache')
        self.assert_(res.find('1234567890') < 0)

    def testVtyGgsn(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('sgsn', ['']))
        self.assertEquals(self.vty.node(), 'config-sgsn')
        self.assertTrue(self.vty.verify('ggsn 0 remote-ip 127.99.99.99', ['']))
        self.assertTrue(self.vty.verify('ggsn 0 gtp-version 1', ['']))
        self.assertTrue(self.vty.verify('apn * ggsn 0', ['']))
        self.assertTrue(self.vty.verify('apn apn1.test ggsn 0', ['']))
        self.assertTrue(self.vty.verify('apn apn1.test ggsn 1', ['% a GGSN with id 1 has not been defined']))
        self.assertTrue(self.vty.verify('apn apn1.test imsi-prefix 123456 ggsn 0', ['']))
        self.assertTrue(self.vty.verify('apn apn2.test imsi-prefix 123456 ggsn 0', ['']))
        res = self.vty.command("show running-config")
        self.assert_(res.find('ggsn 0 remote-ip 127.99.99.99') >= 0)
        self.assert_(res.find('ggsn 0 gtp-version 1') >= 0)
        self.assert_(res.find('apn * ggsn 0') >= 0)
        self.assert_(res.find('apn apn1.test ggsn 0') >= 0)
        self.assert_(res.find('apn apn1.test imsi-prefix 123456 ggsn 0') >= 0)
        self.assert_(res.find('apn apn2.test imsi-prefix 123456 ggsn 0') >= 0)

    def testVtyEasyAPN(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('sgsn', ['']))
        self.assertEquals(self.vty.node(), 'config-sgsn')

        res = self.vty.command("show running-config")
        self.assertEquals(res.find("apn internet"), -1)

        self.assertTrue(self.vty.verify("access-point-name internet.apn", ['']))
        res = self.vty.command("show running-config")
        self.assert_(res.find("apn internet.apn ggsn 0") >= 0)

        self.assertTrue(self.vty.verify("no access-point-name internet.apn", ['']))
        res = self.vty.command("show running-config")
        self.assertEquals(res.find("apn internet"), -1)

    def testVtyCDR(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('sgsn', ['']))
        self.assertEquals(self.vty.node(), 'config-sgsn')

        res = self.vty.command("show running-config")
        self.assert_(res.find("no cdr filename") > 0)

        self.vty.command("cdr filename bla.cdr")
        res = self.vty.command("show running-config")
        self.assertEquals(res.find("no cdr filename"), -1)
        self.assert_(res.find(" cdr filename bla.cdr") > 0)

        self.vty.command("no cdr filename")
        res = self.vty.command("show running-config")
        self.assert_(res.find("no cdr filename") > 0)
        self.assertEquals(res.find(" cdr filename bla.cdr"), -1)

        res = self.vty.command("show running-config")
        self.assert_(res.find(" cdr interval 600") > 0)

        self.vty.command("cdr interval 900")
        res = self.vty.command("show running-config")
        self.assert_(res.find(" cdr interval 900") > 0)
        self.assertEquals(res.find(" cdr interval 600"), -1)

def add_nat_test(suite, workdir):
    if not os.path.isfile(os.path.join(workdir, "src/osmo-bsc_nat/osmo-bsc_nat")):
        print("Skipping the NAT test")
        return
    test = unittest.TestLoader().loadTestsFromTestCase(TestVTYNAT)
    suite.addTest(test)

def nat_bsc_reload(x):
    x.vty.command("configure terminal")
    x.vty.command("nat")
    x.vty.command("bscs-config-file bscs.config")
    x.vty.command("end")

def nat_msc_ip(x, ip, port):
    x.vty.command("configure terminal")
    x.vty.command("nat")
    x.vty.command("msc ip " + ip)
    x.vty.command("msc port " + str(port))
    x.vty.command("end")

def data2str(d):
    return d.encode('hex').lower()

def nat_msc_test(x, ip, port, verbose = False):
    msc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    msc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    msc.settimeout(5)
    msc.bind((ip, port))
    msc.listen(5)
    if (verbose):
        print "MSC is ready at " + ip
    conn = None
    while True:
        vty_response = x.vty.command("show msc connection")
        print "'show msc connection' says: %r" % vty_response
        if vty_response == "MSC is connected: 1":
            # success
            break;
        if vty_response != "MSC is connected: 0":
            raise Exception("Unexpected response to 'show msc connection'"
                            " vty command: %r" % vty_response)

        timeout_retries = 6
        while timeout_retries > 0:
            try:
                conn, addr = msc.accept()
                print "MSC got connection from ", addr
                break
            except socket.timeout:
                print "socket timed out."
                timeout_retries -= 1
                continue

    if not conn:
        raise Exception("VTY reports MSC is connected, but I haven't"
                        " connected yet: %r %r" % (ip, port))
    return msc, conn

def ipa_handle_small(x, verbose = False):
    s = data2str(x.recv(4))
    if len(s) != 4*2:
      raise Exception("expected to receive 4 bytes, but got %d (%r)" % (len(s)/2, s))
    if "0001fe00" == s:
        if (verbose):
            print "\tBSC <- NAT: PING?"
        x.send(IPA().pong())
    elif "0001fe06" == s:
        if (verbose):
            print "\tBSC <- NAT: IPA ID ACK"
        x.send(IPA().id_ack())
    elif "0001fe00" == s:
        if (verbose):
            print "\tBSC <- NAT: PONG!"
    else:
        if (verbose):
            print "\tBSC <- NAT: ", s

def ipa_handle_resp(x, tk, verbose = False, proc=None):
    s = data2str(x.recv(38))
    if "0023fe040108010701020103010401050101010011" in s:
        retries = 3
        while True:
            print "\tsending IPA identity(%s) at %s" % (tk, time.strftime("%T"))
            try:
                x.send(IPA().id_resp(IPA().identity(name = tk.encode('utf-8'))))
                print "\tdone sending IPA identity(%s) at %s" % (tk,
                                                            time.strftime("%T"))
                break
            except:
                print "\tfailed sending IPA identity at", time.strftime("%T")
                if proc:
                  print "\tproc.poll() = %r" % proc.poll()
                if retries < 1:
                    print "\tgiving up"
                    raise
                print "\tretrying (%d attempts left)" % retries
                retries -= 1
    else:
        if (verbose):
            print "\tBSC <- NAT: ", s

def nat_bsc_num_con(x):
    return len(x.vty.command("show bsc connections").split('\n'))

def nat_bsc_sock_test(nr, tk, verbose = False, proc=None):
    bsc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bsc.bind(('127.0.0.1', 0))
    bsc.connect(('127.0.0.1', 5000))
    if (verbose):
        print "BSC%d " %nr
        print "\tconnected to %s:%d" % bsc.getpeername()
    if proc:
      print "\tproc.poll() = %r" % proc.poll()
      print "\tproc.pid = %r" % proc.pid
    ipa_handle_small(bsc, verbose)
    ipa_handle_resp(bsc, tk, verbose, proc=proc)
    if proc:
      print "\tproc.poll() = %r" % proc.poll()
    bsc.recv(27) # MGCP msg
    if proc:
      print "\tproc.poll() = %r" % proc.poll()
    ipa_handle_small(bsc, verbose)
    return bsc

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

def add_sgsn_test(suite, workdir):
    if not os.path.isfile(os.path.join(workdir, "src/gprs/osmo-sgsn")):
        print("Skipping the SGSN test")
        return
    test = unittest.TestLoader().loadTestsFromTestCase(TestVTYSGSN)
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
    parser.add_argument("test_name", nargs="*", help="(parts of) test names to run, case-insensitive")
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
    add_sgsn_test(suite, workdir)

    if args.test_name:
        osmoutil.pick_tests(suite, *args.test_name)

    res = unittest.TextTestRunner(verbosity=verbose_level, stream=sys.stdout).run(suite)
    sys.exit(len(res.errors) + len(res.failures))

# vim: shiftwidth=4 expandtab nocin ai
