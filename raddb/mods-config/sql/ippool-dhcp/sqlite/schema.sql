--
-- Table structure for table 'dhcpippool'
--
CREATE TABLE dhcpstatus (
  status_id		int PRIMARY KEY,
  status		varchar(10) NOT NULL
);

INSERT INTO dhcpstatus (status_id, status) VALUES (1, 'dynamic'), (2, 'static'), (3, 'declined'), (4, 'disabled');

CREATE TABLE dhcpippool (
	id			int(11) PRIMARY KEY,
	pool_name		varchar(30) NOT NULL,
	framedipaddress		varchar(15) NOT NULL default '',
	pool_key		varchar(30) NOT NULL default '',
	gateway			varchar(15) NOT NULL default '',
	expiry_time		DATETIME NOT NULL default (DATETIME('now')),
	status_id		int NOT NULL default 1,
	counter			int NOT NULL default 0,
	FOREIGN KEY(status_id) REFERENCES dhcpstatus(status_id)
);

CREATE INDEX dhcpippool_poolname_expire ON dhcpippool(pool_name, expiry_time);
CREATE INDEX dhcpippool_framedipaddress ON dhcpippool(framedipaddress);
CREATE INDEX dhcpippool_poolname_poolkey_ipaddress ON dhcpippool(pool_name, pool_key, framedipaddress);
