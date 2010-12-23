"Query for one SMS"

Eval [
1 to: 100 do: [:each |
    Transcript show: 'SELECT SMS.* FROM SMS
                        JOIN Subscriber ON SMS.receiver_id = Subscriber.id
                            WHERE SMS.id >= 1 AND SMS.sent IS NULL AND Subscriber.lac > 0
                            ORDER BY SMS.id LIMIT 1;'; nl.
].
]
