"I create output for some simple SQL statements for the HLR db"


Eval [

"Create tables if they don't exist"
Transcript show: 'CREATE TABLE SMS (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created TIMESTAMP NOT NULL,
                    sent TIMESTAMP,
                    sender_id INTEGER NOT NULL,
                    receiver_id INTEGER NOT NULL,
                    deliver_attempts INTEGER NOT NULL DEFAULT 0,
                    valid_until TIMESTAMP,
                    reply_path_req INTEGER NOT NULL,
                    status_rep_req INTEGER NOT NULL,
                    protocol_id INTEGER NOT NULL,
                    data_coding_scheme INTEGER NOT NULL,
                    ud_hdr_ind INTEGER NOT NULL,
                    dest_addr TEXT,
                    user_data BLOB,
                    header BLOB,
                    text TEXT);'; nl;
	     show: 'CREATE TABLE Subscriber (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created TIMESTAMP NOT NULL,
                    updated TIMESTAMP NOT NULL,
                    imsi NUMERIC UNIQUE NOT NULL,
                    name TEXT,
                    extension TEXT UNIQUE,
                    authorized INTEGER NOT NULL DEFAULT 0,
                    tmsi TEXT UNIQUE,
                    lac INTEGER NOT NULL DEFAULT 0);'; nl.

"Create some dummy subscribers"
num_sub := 1000.
num_sms := 30.
lac := 1.

Transcript show: 'BEGIN;'; nl.

1 to: num_sub do: [:each |
   Transcript show: 'INSERT INTO Subscriber
                        (imsi, created, updated, authorized, lac, extension)
                        VALUES
                        (%1, datetime(''now''), datetime(''now''), 1, %2, %3);' %
                        {(274090000000000 + each). lac. each}; nl.
].

1 to: num_sms do: [:sms |
    1 to: num_sub do: [:sub |
        Transcript show: 'INSERT INTO SMS
                            (created, sender_id, receiver_id, valid_until,
                             reply_path_req, status_rep_req, protocol_id,
                             data_coding_scheme, ud_hdr_ind, dest_addr,
                             text) VALUES
                            (datetime(''now''), 1, %1, ''2222-2-2'',
                             0, 0, 0,
                             0, 0, ''123456'',
                             ''abc'');' % {sub}; nl.
    ]
].

Transcript show: 'COMMIT;'; nl.

]
