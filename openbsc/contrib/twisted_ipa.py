#!/usr/bin/python3
# -*- mode: python-mode; py-indent-tabs-mode: nil -*-
"""
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
"""

__version__ = "0.6" # bump this on every non-trivial change

from ipa import Ctrl, IPA
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.internet import reactor
from twisted.protocols import basic
import argparse, logging

class IPACommon(basic.Int16StringReceiver):
    """
    Generic IPA protocol handler: include some routines for simpler subprotocols.
    It's not intended as full implementation of all subprotocols, rather common ground and example code.
    """
    def dbg(self, line):
        """
        Debug print helper
        """
        self.factory.log.debug(line)

    def osmo_CTRL(self, data):
        """
        OSMO CTRL protocol
        Placeholder, see corresponding derived class
        """
        pass

    def osmo_MGCP(self, data):
        """
        OSMO MGCP extension
        """
        self.dbg('OSMO MGCP received %s' % data)

    def osmo_LAC(self, data):
        """
        OSMO LAC extension
        """
        self.dbg('OSMO LAC received %s' % data)

    def osmo_SMSC(self, data):
        """
        OSMO SMSC extension
        """
        self.dbg('OSMO SMSC received %s' % data)

    def osmo_ORC(self, data):
        """
        OSMO ORC extension
        """
        self.dbg('OSMO ORC received %s' % data)

    def osmo_GSUP(self, data):
        """
        OSMO GSUP extension
        """
        self.dbg('OSMO GSUP received %s' % data)

    def osmo_OAP(self, data):
        """
        OSMO OAP extension
        """
        self.dbg('OSMO OAP received %s' % data)

    def osmo_UNKNOWN(self, data):
        """
        OSMO defaul extension handler
        """
        self.dbg('OSMO unknown extension received %s' % data)

    def handle_RSL(self, data, proto, extension):
        """
        RSL protocol handler
        """
        self.dbg('IPA RSL received message with extension %s' % extension)

    def handle_CCM(self, data, proto, msgt):
        """
        CCM (IPA Connection Management)
        Placeholder, see corresponding derived class
        """
        pass

    def handle_SCCP(self, data, proto, extension):
        """
        SCCP protocol handler
        """
        self.dbg('IPA SCCP received message with extension %s' % extension)

    def handle_OML(self, data, proto, extension):
        """
        OML protocol handler
        """
        self.dbg('IPA OML received message with extension %s' % extension)

    def handle_OSMO(self, data, proto, extension):
        """
        Dispatcher point for OSMO subprotocols based on extension name, lambda default should never happen
        """
        method = getattr(self, 'osmo_' + IPA().ext(extension), lambda: "extension dispatch failure")
        method(data)

    def handle_MGCP(self, data, proto, extension):
        """
        MGCP protocol handler
        """
        self.dbg('IPA MGCP received message with attribute %s' % extension)

    def handle_UNKNOWN(self, data, proto, extension):
        """
        Default protocol handler
        """
        self.dbg('IPA received message for %s (%s) protocol with attribute %s' % (IPA().proto(proto), proto, extension))

    def process_chunk(self, data):
        """
        Generic message dispatcher for IPA (sub)protocols based on protocol name, lambda default should never happen
        """
        (_, proto, extension, content) = IPA().del_header(data)
        if content is not None:
            self.dbg('IPA received %s::%s [%d/%d] %s' % (IPA().proto(proto), IPA().ext_name(proto, extension), len(data), len(content), content))
            method = getattr(self, 'handle_' + IPA().proto(proto), lambda: "protocol dispatch failure")
            method(content, proto, extension)

    def dataReceived(self, data):
        """
        Override for dataReceived from Int16StringReceiver because of inherently incompatible interpretation of length
        If default handler is used than we would always get off-by-1 error (Int16StringReceiver use equivalent of l + 2)
        """
        if len(data):
            (head, tail) = IPA().split_combined(data)
            self.process_chunk(head)
            self.dataReceived(tail)

    def connectionMade(self):
        """
        We have to resetDelay() here to drop internal state to default values to make reconnection logic work
        Make sure to call this via super() if overriding to keep reconnection logic intact
        """
        addr = self.transport.getPeer()
        self.dbg('IPA connected to %s:%d peer' % (addr.host, addr.port))
        self.factory.resetDelay()


class CCM(IPACommon):
    """
    Implementation of CCM protocol for IPA multiplex
    """
    def ack(self):
        self.transport.write(IPA().id_ack())

    def ping(self):
        self.transport.write(IPA().ping())

    def pong(self):
        self.transport.write(IPA().pong())

    def handle_CCM(self, data, proto, msgt):
        """
        CCM (IPA Connection Management)
        Only basic logic necessary for tests is implemented (ping-pong, id ack etc)
        """
        if msgt == IPA.MSGT['ID_GET']:
            self.transport.getHandle().sendall(IPA().id_resp(self.factory.ccm_id))
            # if we call
            # self.transport.write(IPA().id_resp(self.factory.test_id))
            # instead, than we would have to also call
            # reactor.callLater(1, self.ack)
            # instead of self.ack()
            # otherwise the writes will be glued together - hence the necessity for ugly hack with 1s timeout
            # Note: this still might work depending on the IPA implementation details on the other side
            self.ack()
            # schedule PING in 4s
            reactor.callLater(4, self.ping)
        if msgt == IPA.MSGT['PING']:
            self.pong()


class CTRL(IPACommon):
    """
    Implementation of Osmocom control protocol for IPA multiplex
    """
    def ctrl_SET(self, data, op_id, v):
        """
        Handle CTRL SET command
        """
        self.dbg('CTRL SET [%s] %s' % (op_id, v))

    def ctrl_SET_REPLY(self, data, op_id, v):
        """
        Handle CTRL SET reply
        """
        self.dbg('CTRL SET REPLY [%s] %s' % (op_id, v))

    def ctrl_GET(self, data, op_id, v):
        """
        Handle CTRL GET command
        """
        self.dbg('CTRL GET [%s] %s' % (op_id, v))

    def ctrl_GET_REPLY(self, data, op_id, v):
        """
        Handle CTRL GET reply
        """
        self.dbg('CTRL GET REPLY [%s] %s' % (op_id, v))

    def ctrl_TRAP(self, data, op_id, v):
        """
        Handle CTRL TRAP command
        """
        self.dbg('CTRL TRAP [%s] %s' % (op_id, v))

    def ctrl_ERROR(self, data, op_id, v):
        """
        Handle CTRL ERROR reply
        """
        self.dbg('CTRL ERROR [%s] %s' % (op_id, v))

    def osmo_CTRL(self, data):
        """
        OSMO CTRL message dispatcher, lambda default should never happen
        For basic tests only, appropriate handling routines should be replaced: see CtrlServer for example
        """
        self.dbg('OSMO CTRL received %s::%s' % Ctrl().parse(data.decode('utf-8')))
        (cmd, op_id, v) = data.decode('utf-8').split(' ', 2)
        method = getattr(self, 'ctrl_' + cmd, lambda: "CTRL unknown command")
        method(data, op_id, v)


class IPAServer(CCM):
    """
    Test implementation of IPA server
    Demonstrate CCM opearation by overriding necessary bits from CCM
    """
    def connectionMade(self):
        """
        Keep reconnection logic working by calling routine from CCM
        Initiate CCM upon connection
        """
        addr = self.transport.getPeer()
        self.factory.log.info('IPA server: connection from %s:%d client' % (addr.host, addr.port))
        super(IPAServer, self).connectionMade()
        self.transport.write(IPA().id_get())


class CtrlServer(CTRL):
    """
    Test implementation of CTRL server
    Demonstarte CTRL handling by overriding simpler routines from CTRL
    """
    def connectionMade(self):
        """
        Keep reconnection logic working by calling routine from CTRL
        Send TRAP upon connection
        Note: we can't use sendString() because of it's incompatibility with IPA interpretation of length prefix
        """
        addr = self.transport.getPeer()
        self.factory.log.info('CTRL server: connection from %s:%d client' % (addr.host, addr.port))
        super(CtrlServer, self).connectionMade()
        self.transport.write(Ctrl().trap('LOL', 'what'))
        self.transport.write(Ctrl().trap('rulez', 'XXX'))

    def reply(self, r):
        self.transport.write(Ctrl().add_header(r))

    def ctrl_SET(self, data, op_id, v):
        """
        CTRL SET command: always succeed
        """
        self.dbg('SET [%s] %s' % (op_id, v))
        self.reply('SET_REPLY %s %s' % (op_id, v))

    def ctrl_GET(self, data, op_id, v):
        """
        CTRL GET command: always fail
        """
        self.dbg('GET [%s] %s' % (op_id, v))
        self.reply('ERROR %s No variable found' % op_id)


class IPAFactory(ReconnectingClientFactory):
    """
    Generic IPA Client Factory which can be used to store state for various subprotocols and manage connections
    Note: so far we do not really need separate Factory for acting as a server due to protocol simplicity
    """
    protocol = IPACommon
    log = None
    ccm_id = IPA().identity(unit=b'1515/0/1', mac=b'b0:0b:fa:ce:de:ad:be:ef', utype=b'sysmoBTS', name=b'StingRay', location=b'hell', sw=IPA.version.encode('utf-8'))

    def __init__(self, proto=None, log=None, ccm_id=None):
        if proto:
            self.protocol = proto
        if ccm_id:
            self.ccm_id = ccm_id
        if log:
            self.log = log
        else:
            self.log = logging.getLogger('IPAFactory')
            self.log.setLevel(logging.CRITICAL)
            self.log.addHandler(logging.NullHandler)

    def clientConnectionFailed(self, connector, reason):
        """
        Only necessary for as debugging aid - if we can somehow set parent's class noisy attribute then we can omit this method
        """
        self.log.warning('IPAFactory connection failed: %s' % reason.getErrorMessage())
        ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)

    def clientConnectionLost(self, connector, reason):
        """
        Only necessary for as debugging aid - if we can somehow set parent's class noisy attribute then we can omit this method
        """
        self.log.warning('IPAFactory connection lost: %s' % reason.getErrorMessage())
        ReconnectingClientFactory.clientConnectionLost(self, connector, reason)


if __name__ == '__main__':
    p = argparse.ArgumentParser("Twisted IPA (module v%s) app" % IPA.version)
    p.add_argument('-v', '--version', action='version', version="%(prog)s v" + __version__)
    p.add_argument('-p', '--port', type=int, default=4250, help="Port to use for CTRL interface")
    p.add_argument('-d', '--host', default='localhost', help="Adress to use for CTRL interface")
    cs = p.add_mutually_exclusive_group()
    cs.add_argument("-c", "--client", action='store_true', help="asume client role")
    cs.add_argument("-s", "--server", action='store_true', help="asume server role")
    ic = p.add_mutually_exclusive_group()
    ic.add_argument("--ipa", action='store_true', help="use IPA protocol")
    ic.add_argument("--ctrl", action='store_true', help="use CTRL protocol")
    args = p.parse_args()
    test = False

    log = logging.getLogger('TwistedIPA')
    log.setLevel(logging.DEBUG)
    log.addHandler(logging.StreamHandler(sys.stdout))

    if args.ctrl:
        if args.client:
            # Start osmo-bsc to receive TRAP messages when osmo-bts-* connects to it
            print('CTRL client, connecting to %s:%d' % (args.host, args.port))
            reactor.connectTCP(args.host, args.port, IPAFactory(CTRL, log))
            test = True
        if args.server:
            # Use bsc_control.py to issue set/get commands
            print('CTRL server, listening on port %d' % args.port)
            reactor.listenTCP(args.port, IPAFactory(CtrlServer, log))
            test = True
    if args.ipa:
        if args.client:
            # Start osmo-nitb which would initiate A-bis/IP session
            print('IPA client, connecting to %s ports %d and %d' % (args.host, IPA.TCP_PORT_OML, IPA.TCP_PORT_RSL))
            reactor.connectTCP(args.host, IPA.TCP_PORT_OML, IPAFactory(CCM, log))
            reactor.connectTCP(args.host, IPA.TCP_PORT_RSL, IPAFactory(CCM, log))
            test = True
        if args.server:
            # Start osmo-bts-* which would attempt to connect to us
            print('IPA server, listening on ports %d and %d' % (IPA.TCP_PORT_OML, IPA.TCP_PORT_RSL))
            reactor.listenTCP(IPA.TCP_PORT_RSL, IPAFactory(IPAServer, log))
            reactor.listenTCP(IPA.TCP_PORT_OML, IPAFactory(IPAServer, log))
            test = True
    if test:
        reactor.run()
    else:
        print("Please specify which protocol in which role you'd like to test.")
