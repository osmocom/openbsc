#!/usr/bin/python

import sys
import string
import random
import binascii
import sip_parser
import re
from twisted.internet import defer
from twisted.internet import protocol
from twisted.python import log
from twisted.protocols import sip
from time import sleep

TCP_SRC_IP   = "127.0.0.1"
TCP_SRC_PORT = 5060

class RegistrationProxyServer(protocol.Protocol):
    src_ip = TCP_SRC_IP
    src_port = TCP_SRC_PORT

    def connectionMade(self):
        self.ussd_queue = defer.DeferredQueue()
        self.ussd_queue.get().addCallback(self.sipClientDataReceived)
        from twisted.internet import reactor
        #reactor.listenTCP(UDP_TCP_PORT, self.sip_client_factory)

    def sipClientDataReceived(self, data):
        log.msg("\n[USSD:RX]\n%s" % data)
        if data:
          self.ussd_queue.get().addCallback(self.sipClientDataReceived)

          msgType, firstLine, headers, body = sip_parser.parseSipMessage(data)
          via = headers["via"][0].split(";")
          via_branch = via[1].split("=")
          from_hdr = headers["from"].split(";")
          from_tag = from_hdr[1]
          to_hdr = headers["to"].split(";")
          to_tag = "%s" % from_hdr[1]
          call_id = headers["call-id"]
          sip_url = re.split(r"[:@]", from_hdr[0])
          ussd_url = sip_url[1]
          try:
              contact = headers["contact"].split("@")
          except:
              pass
          cseq = headers["cseq"]
          via_dest_ip,via_dest_port=via[0].split(" ")[1].split(":")

          if msgType=="INVITE":
              #sleep(5)

              r = sip.Response(200, "OK")
              r.addHeader('Via',  headers["via"][0]) #sip.Via(via_dest_ip, via_dest_port, transport='TCP', ttl=None, hidden=False, received=None, rport=None, branch=via_branch[1], maddr=None).toString())
              r.addHeader('From', "%s;%s" % (from_hdr[0], from_tag)) #"<sip:%s@%s>;%s" % (from_hdr[0], self.src_ip, from_tag))
              r.addHeader('To', "%s;%s" % (to_hdr[0], to_tag)) #"<sip:%s@%s>;%s" % (to_hdr[0], self.src_ip, to_tag))
              r.addHeader('Call-Id', call_id)
              r.addHeader('Max-Forwards', 20)
              r.addHeader('Cseq',  cseq)
              r.addHeader('Contact',  '<sip:test@127.0.0.1:5060>')
              r.addHeader('Recv-Info', 'g.3gpp.ussd')
              r.addHeader('Content-Length', 0)
              #r.addHeader("Authentication-Info", auth_info)
              log.msg("\n[SIP:TX]\n%s" % r.toString())
              self.transport.write(r.toString())

              r = sip.Response(100, "Trying")
              r.addHeader('Via',  headers["via"][0]) #sip.Via(via_dest_ip, via_dest_port, transport='TCP', ttl=None, hidden=False, received=None, rport=None, branch=via_branch[1], maddr=None).toString())
              r.addHeader('From', "%s;%s" % (from_hdr[0], from_tag)) #"<sip:%s@%s>;%s" % (from_hdr[0], self.src_ip, from_tag))
              r.addHeader('To', "%s;%s" % (to_hdr[0], to_tag)) #"<sip:%s@%s>;%s" % (to_hdr[0], self.src_ip, to_tag))
              r.addHeader('Call-Id', call_id)
              r.addHeader('Max-Forwards', 20)
              r.addHeader('Cseq',  cseq)
              r.addHeader('Contact',  '<sip:test@127.0.0.1:5060>')
              r.addHeader('Content-Length', 0)
              log.msg("\n[SIP:TX]\n%s" % r.toString())
              self.transport.write(r.toString())


          elif msgType=="ACK" and to_hdr[0].startswith("<sip:*101"):
              msg = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ussd-data><language>en</language><ussd-string>%s</ussd-string></ussd-data>" % (
                                "Select Item from menu:\n1) Option 1\n2) Option 2");

              r = sip.Request("INFO", to_hdr[0].replace('<', '').replace('>', ''))
              r.addHeader('Via', headers["via"][0]) #sip.Via(via_dest_ip, via_dest_port, transport='TCP', ttl=None, hidden=False, received=None, rport=None, branch=via_branch[1], maddr=None).toString())
              r.addHeader('From', "%s;%s" % (from_hdr[0], to_tag)) #"<sip:%s@%s>;%s" % (from_hdr[0], self.src_ip, from_tag))
              r.addHeader('To', "%s;%s" % (to_hdr[0], from_tag)) #"<sip:%s@%s>;%s" % (to_hdr[0], self.src_ip, to_tag))
              r.addHeader('Call-Id', call_id)
              r.addHeader('Max-Forwards', 20)
              r.addHeader('Cseq',  "%d INFO" % (int(cseq.split(' ')[0]) + 1))
              r.addHeader('Recv-Info', 'g.3gpp.ussd')
              r.addHeader('Content-Type', 'application/vnd.3gpp.ussd+xml')
              #r.addHeader('Content-Disposition', 'Info-Package')
              r.addHeader('Content-Length', len(msg))
              #r.addHeader("Authentication-Info", auth_info)
              log.msg("\n[SIP:TX]]\n%s" % r.toString())
              self.transport.write(r.toString() + msg)

          elif msgType=="ACK" or msgType=="INFO":
              msg = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ussd-data><language>en</language><ussd-string>%s</ussd-string></ussd-data>" % (
                                "Test");
              if msgType=="INFO":
                  r = sip.Response(200, "OK")
                  r.addHeader('Via',  headers["via"][0]) #sip.Via(via_dest_ip, via_dest_port, transport='TCP', ttl=None, hidden=False, received=None, rport=None, branch=via_branch[1], maddr=None).toString())
                  r.addHeader('From', "%s;%s" % (from_hdr[0], from_tag)) #"<sip:%s@%s>;%s" % (from_hdr[0], self.src_ip, from_tag))
                  r.addHeader('To', "%s;%s" % (to_hdr[0], to_tag)) #"<sip:%s@%s>;%s" % (to_hdr[0], self.src_ip, to_tag))
                  r.addHeader('Call-Id', call_id)
                  r.addHeader('Max-Forwards', 20)
                  r.addHeader('Cseq',  cseq)
                  r.addHeader('Recv-Info', 'g.3gpp.ussd')
                  r.addHeader('Content-Length', 0)
                  #r.addHeader("Authentication-Info", auth_info)
                  log.msg("\n[SIP:TX]\n%s" % r.toString())
                  self.transport.write(r.toString())


              r = sip.Request("BYE", to_hdr[0].replace('<', '').replace('>', ''))
              r.addHeader('Via', headers["via"][0]) #sip.Via(via_dest_ip, via_dest_port, transport='TCP', ttl=None, hidden=False, received=None, rport=None, branch=via_branch[1], maddr=None).toString())
              r.addHeader('From', "%s;%s" % (from_hdr[0], to_tag)) #"<sip:%s@%s>;%s" % (from_hdr[0], self.src_ip, from_tag))
              r.addHeader('To', "%s;%s" % (to_hdr[0], from_tag)) #"<sip:%s@%s>;%s" % (to_hdr[0], self.src_ip, to_tag))
              r.addHeader('Call-Id', call_id)
              r.addHeader('Max-Forwards', 20)
              r.addHeader('Cseq',  "%d BYE" % (int(cseq.split(' ')[0]) + 1))
              r.addHeader('Recv-Info', 'g.3gpp.ussd')
              r.addHeader('Content-Type', 'application/vnd.3gpp.ussd+xml')
              #r.addHeader('Content-Disposition', 'Info-Package')
              r.addHeader('Content-Length', len(msg))
              #r.addHeader("Authentication-Info", auth_info)
              log.msg("\n[SIP:TX]]\n%s" % r.toString())
              self.transport.write(r.toString() + msg)
          else:
              print msgType

          #self.ussd_queue.get().addCallback(self.sipClientDataReceived)
          #self.ussd_queue.get().addCallback(self.sipClientDataReceived)

    def dataReceived(self, data):
          #log.msg("\n[IMSI:RX] [Proxy <=============== BSC]\n%s" % data)
          self.ussd_queue.put(data)

class RegistrationProxyServerFactory(protocol.ClientFactory):
    protocol = RegistrationProxyServer

if __name__ == "__main__":
    log.startLogging(sys.stdout)
    factory = RegistrationProxyServerFactory()
    from twisted.internet import reactor
    reactor.listenTCP(TCP_SRC_PORT, factory)
    reactor.run()


