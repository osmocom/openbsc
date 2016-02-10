################################################################################
#
# Stand-alone VoIP honeypot client (preparation for Dionaea integration)
# Copyright (c) 2010 Tobias Wulff (twu200 at gmail)
#
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
################################################################################


import sys
import string

# SIP headers have short forms
shortHeaders = {"call-id": "i",
                "contact": "m",
                "content-encoding": "e",
                "content-length": "l",
                "content-type": "c",
                "from": "f",
                "subject": "s",
                "to": "t",
                "via": "v",
                                "cseq": "cseq",
                                "accept": "accept",
                                "user-agent": "user-agent",
                                "max-forwards": "max-forwards",
                                "www-authentication": "www-authentication",
                                "authorization": "authorization",
                                "allow": "allow",
                                "recv-info": "recv-info",
                                "supported": "supported"
                }

longHeaders = {}
for k, v in shortHeaders.items():
    longHeaders[v] = k
del k, v

class SipParsingError(Exception):
        """Exception class for errors occuring during SIP message parsing"""

def parseSipMessage(msg):
        """Parses a SIP message (string), returns a tupel (type, firstLine, header,
        body)"""
        # Sanitize input: remove superfluous leading and trailing newlines and
        # spaces
        msg = msg.strip("\n\r\t ")

        # Split request/status line plus headers and body: we don't care about the
        # body in the SIP parser
        parts = msg.split("\n\r\n", 1)
        if len(parts) < 1:
                raise SipParsingError("Message too short")

        msg = parts[0]

        # Python way of doing a ? b : c
        body = len(parts) == 2 and parts[1] or parts[len(parts)-1]

        # Normalize line feed and carriage return to \n
        msg = msg.replace("\n\r", "\n")

        # Split lines into a list, each item containing one line
        lines = msg.split('\n')

        # Get message type (first word, smallest possible one is "ACK" or "BYE")
        sep = lines[0].find(' ')
        if sep < 3:
                raise SipParsingError("Malformed request or status line")

        msgType = lines[0][:sep]
        firstLine = lines[0][sep+1:]

        # Done with first line: delete from list of lines
        del lines[0]

        # Parse header
        headers = {}
        for i in range(len(lines)):
                # Take first line and remove from list of lines
                line = lines.pop(0)

                # Strip each line of leading and trailing whitespaces
                line = line.strip("\n\r\t ")

                # Break on empty line (end of headers)
                if len(line.strip(' ')) == 0:
                        break

                # Parse header lines
                sep = line.find(':')
                if sep < 1:
                        raise SipParsingError("Malformed header line (no ':')")

                # Get header identifier (word before the ':')
                identifier = line[:sep]
                identifier = identifier.lower()

                # Check for valid header
                if identifier not in shortHeaders.keys() and \
                        identifier not in longHeaders.keys():
                        raise SipParsingError("Unknown header type: {}".format(identifier))

                # Get long header identifier if necessary
                if identifier in longHeaders.keys():
                        identifier = longHeaders[identifier]

                # Get header value (line after ':')
                value = line[sep+1:].strip(' ')

                # The Via header can occur multiple times
                if identifier == "via":
                        if identifier not in headers:
                                headers["via"] = [value]
                        else:
                                headers["via"].append(value)

                # Assign any other header value directly to the header key
                else:
                        headers[identifier] = value

        # Return message type, header dictionary, and body string
        return (msgType, firstLine, headers, body)
