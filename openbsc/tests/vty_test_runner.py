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


class TestVTYNAT(TestVTYBase):

    def vty_command(self):
        return ["./src/osmo-bsc_nat/osmo-bsc_nat", "-c",
                "doc/examples/osmo-bsc_nat/osmo-bsc_nat.cfg"]

    def vty_app(self):
        return (4244, "src/osmo-bsc_nat/osmo-bsc_nat",  "OsmoBSCNAT", "nat")

    def testMoo(self):
        pass


def add_nat_test(suite, workdir):
    if not os.path.isfile(os.path.join(workdir, "src/osmo-bsc_nat/osmo-bsc_nat")):
        print("Skipping the NAT test")
        return
    test = unittest.TestLoader().loadTestsFromTestCase(TestVTYNAT)
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
    add_nat_test(suite, workdir)
    res = unittest.TextTestRunner(verbosity=verbose_level).run(suite)
    sys.exit(len(res.errors) + len(res.failures))
