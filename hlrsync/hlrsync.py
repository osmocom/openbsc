#!/usr/bin/python2.5

from __future__ import with_statement

from pysqlite2 import dbapi2 as sqlite3
import sys

hlr = sqlite3.connect(sys.argv[1])
web = sqlite3.connect(sys.argv[2])

# switch to autocommit
hlr.isolation_level = None
web.isolation_level = None

hlr.row_factory = sqlite3.Row
web.row_factory = sqlite3.Row

with hlr:
	hlr_subscrs = hlr.execute("""
		SELECT * FROM Subscriber
	""").fetchall()
	hlr_tokens = hlr.execute("""
		SELECT * FROM AuthToken
	""").fetchall()

with web:
	web_tokens = web.execute("""
		SELECT * FROM reg_tokens
	""").fetchall()
	web_sms = web.execute("""
		SELECT * FROM sms_queue
	""").fetchall()

# index by subscr id
hlr_subscrs_by_id = {}
hlr_subscrs_by_ext = {}
hlr_tokens_by_subscr_id = {}
for x in hlr_subscrs:
	hlr_subscrs_by_id[x['id']] = x
	hlr_subscrs_by_ext[x['extension']] = x
del hlr_subscrs
for x in hlr_tokens:
	hlr_tokens_by_subscr_id[x['subscriber_id']] = x
del hlr_tokens

web_tokens_by_subscr_id = {}
for x in web_tokens:
	web_tokens_by_subscr_id[x['subscriber_id']] = x
del web_tokens

# remove leftover web_tokens and correct inconsistent fields
with web:
	for x in web_tokens_by_subscr_id.values():
		subscr = hlr_subscrs_by_id.get(x['subscriber_id'], None)
		if subscr is None:
			web.execute("""
				      DELETE FROM reg_tokens WHERE subscriber_id = ?
				   """, (x['subscriber_id'],))
			del web_tokens_by_subscr_id[x['subscriber_id']]
			continue
		if str(x['imsi']) != str(subscr['imsi']) or \
		   x['extension'] != subscr['extension'] or \
		   x['tmsi'] != subscr['tmsi'] or \
		   x['lac'] != subscr['lac']:
			web.execute("""
				      UPDATE reg_tokens
				      SET imsi = ?, extension = ?, tmsi = ?, lac = ?
				      WHERE subscriber_id = ?
				   """, (str(subscr['imsi']), subscr['extension'],
				   subscr['tmsi'], subscr['lac'], x['subscriber_id']))

# add missing web_tokens
with web:
	for x in hlr_tokens_by_subscr_id.values():
		subscr = hlr_subscrs_by_id.get(x['subscriber_id'], None)
		if subscr is None:
			hlr.execute("""
				      DELETE FROM AuthToken WHERE subscriber_id = ?
				   """, (x['subscriber_id'],))
			del hlr_tokens_by_subscr_id[x['subscriber_id']]
			continue
		webtoken = web_tokens_by_subscr_id.get(x['subscriber_id'], None)
		if webtoken is None:
			web.execute("""
				      INSERT INTO reg_tokens
				      (subscriber_id, extension, reg_completed, name, email, lac, imsi, token, tmsi)
				      VALUES
				      (?, ?, 0, ?, '', ?, ?, ?, ?)
				   """, (x['subscriber_id'], subscr['extension'], subscr['name'],
				   subscr['lac'], str(subscr['imsi']), x['token'], subscr['tmsi']))

# authorize subscribers
with hlr:
	for x in web_tokens_by_subscr_id.values():
		subscr = hlr_subscrs_by_id.get(x['subscriber_id'], None)
		if x['reg_completed'] and not subscr['authorized']:
			hlr.execute("""
				      UPDATE Subscriber
				      SET authorized = 1
				      WHERE id = ?
				   """, (x['subscriber_id'],))

# Sync SMS from web to hlr
with hlr:
	for sms in web_sms:
		subscr = hlr_subscrs_by_ext.get(sms['receiver_ext'])
		if subscr is None:
			print '%s not found' % sms['receiver_ext']
			continue
		hlr.execute("""
				      INSERT INTO SMS
				      (created, sender_id, receiver_id, reply_path_req, status_rep_req, protocol_id, data_coding_scheme, ud_hdr_ind, text)
				      VALUES
				      (?, 1, ?, 0, 0, 0, 0, 0, ?)
				   """, (sms['created'], subscr['id'], sms['text']))
with web:
	for sms in web_sms:
		web.execute("""
				      DELETE FROM sms_queue WHERE id = ?
				   """, (sms['id'],))


hlr.close()
web.close()

