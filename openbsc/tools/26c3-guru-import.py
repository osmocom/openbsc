#!/usr/bin/python2.6

# Based loosely on hlrsync.py from Jan Lübbe
# (C) 2009 Daniel Willmann
# All Rights Reserved
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

from __future__ import with_statement

import urllib
from pysqlite2 import dbapi2 as sqlite3
import sys

hlr = sqlite3.connect(sys.argv[1])
web = urllib.urlopen(sys.argv[2]).read()

# switch to autocommit
hlr.isolation_level = None

hlr.row_factory = sqlite3.Row

web = web.split("\n")

# Remove last empty newline
# List of extension - imei/imsi tuples from GURU2
web_tuple = [ (int(i.split(" ")[0]), int(i.split(" ")[1])) for i in web if len(i) > 0 ]

for x in web_tuple:
	exten = x[0]
	imxi = x[1]

	# Enforce numering plan of 26c3
	if exten < 9100 or exten > 9999:
		continue

	# Test if it is an IMSI and hasn't yet been authorized
	subscr = hlr.execute("""
		SELECT * FROM Subscriber WHERE imsi=="%015u" and authorized==0
	""" % (imxi) ).fetchall()

	# Not an IMSI
	if len(subscr) == 0:
		equip = hlr.execute("""
			SELECT * FROM Equipment WHERE imei="%015u"
		""" % (imxi) ).fetchall();
		#print equip

		if len(equip) == 0:
			continue

		subscrid = hlr.execute("""
			SELECT * FROM EquipmentWatch WHERE equipment_id=%015u ORDER BY created LIMIT 1
		""" % (int(equip[0]['id'])) ).fetchall();

		#print subscrid

		if len(subscrid) == 0:
			continue

		subscr = hlr.execute("""
			SELECT * FROM Subscriber WHERE id==%u and authorized==0
		""" % subscrid[0]['subscriber_id']).fetchall();

	if len(subscr) == 0:
		continue

	subscr = subscr[0]
	# Now we have an unauthorized subscriber for the imXi
	print exten, imxi
	print subscr

	# Strip leading 9 from extension and authorize subscriber
	hlr.execute("""UPDATE Subscriber SET authorized = 1,extension="%s" \
	    WHERE id = %u
	""" % (str(exten)[1:], subscr['id']) );

hlr.close()
