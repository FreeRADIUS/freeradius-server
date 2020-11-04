--
-- Table structure for table 'fr_ippool'
--
CREATE TABLE fr_ippool_status (
  status_id             int PRIMARY KEY,
  status		varchar(10) NOT NULL
);

INSERT INTO fr_ippool_status (status_id, status) VALUES (1, 'dynamic'), (2, 'static'), (3, 'declined'), (4, 'disabled');

CREATE TABLE fr_ippool (
	id			int PRIMARY KEY,
	pool_name		varchar(30) NOT NULL,
	address		varchar(15) NOT NULL,
	owner		varchar(30) NOT NULL DEFAULT '',
	gateway			varchar(15) NOT NULL DEFAULT '',
	expiry_time		DATETIME NOT NULL default (DATETIME('now')),
	status_id		int NOT NULL DEFAULT 1,
	counter			int NOT NULL DEFAULT 0,
	FOREIGN KEY(status_id) REFERENCES fr_ippool_status(status_id)
);

CREATE INDEX fr_ippool_poolname_expire ON fr_ippool(pool_name, expiry_time);
CREATE INDEX fr_ippool_address ON fr_ippool(address);
CREATE INDEX fr_ippool_poolname_poolkey ON fr_ippool(pool_name, owner, address);

-- Example of how to put IPs in the pool
-- INSERT INTO fr_ippool (pool_name, address) VALUES ('local', '192.168.5.10');
-- INSERT INTO fr_ippool (pool_name, address) VALUES ('local', '192.168.5.11');
-- INSERT INTO fr_ippool (pool_name, address) VALUES ('local', '192.168.5.12');
-- INSERT INTO fr_ippool (pool_name, address) VALUES ('local', '192.168.5.13');

