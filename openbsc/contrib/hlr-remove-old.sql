-- Remove old data from the database
DELETE FROM Subscriber
	WHERE id != 1 AND datetime('now', '-10 days') > updated AND authorized != 1;
DELETE FROM Equipment
	WHERE datetime('now', '-10 days') > updated;
DELETE FROM EquipmentWatch
	WHERE datetime('now', '-10 days') > updated;
DELETE FROM SMS
	WHERE datetime('now', '-10 days') > created;
DELETE FROM VLR
	WHERE datetime('now', '-10 days') > updated;
DELETE FROM ApduBlobs
	WHERE datetime('now', '-10 days') > created;
DELETE FROM Counters
	WHERE datetime('now', '-10 days') > timestamp;
DELETE FROM RateCounters
	WHERE datetime('now', '-10 days') > timestamp;
VACUUM;
