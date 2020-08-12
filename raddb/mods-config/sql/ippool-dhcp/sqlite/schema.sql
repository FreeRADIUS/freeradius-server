--
-- Table structure for table 'dhcpippool'
--
CREATE TABLE dhcpstatus (
  status_id             int PRIMARY KEY,
  status		varchar(10) NOT NULL
)

INSERT INTO dhcpstatus (status_id, status) VALUES (1, 'dynamic'), (2, 'static'), (3, 'declined'), (4, 'disabled');

CREATE TABLE dhcpippool (
	id			int PRIMARY KEY,
	pool_name		varchar(30) NOT NULL,
	framedipaddress		varchar(15) NOT NULL,
	pool_key		varchar(30) NOT NULL DEFAULT '',
	gateway			varchar(15) NOT NULL DEFAULT '',
	expiry_time		DATETIME NOT NULL default (DATETIME('now')),
	status_id		int NOT NULL DEFAULT 1,
	FOREIGN KEY(status_id) REFERENCES dhcpstatus(status_id)
);

CREATE INDEX dhcpippool_poolname_expire ON dhcpippool(pool_name, expiry_time);
CREATE INDEX dhcpippool_framedipaddress ON dhcpippool(framedipaddress);
CREATE INDEX dhcpippool_poolname_poolkey ON dhcpippool(pool_name, pool_key, framedipaddress);

-- Example of how to put IPs in the pool
-- INSERT INTO radippool (pool_name, framedipaddress) VALUES ('local', '192.168.5.10');
-- INSERT INTO radippool (pool_name, framedipaddress) VALUES ('local', '192.168.5.11');
-- INSERT INTO radippool (pool_name, framedipaddress) VALUES ('local', '192.168.5.12');
-- INSERT INTO radippool (pool_name, framedipaddress) VALUES ('local', '192.168.5.13');

