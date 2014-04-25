CREATE TABLE radippool (
	id                      int PRIMARY KEY,
	pool_name               varchar(30) NOT NULL,
	framedipaddress         varchar(30) NOT NULL,
	nasipaddress            varchar(30) NOT NULL DEFAULT '',
	pool_key                varchar(64) NOT NULL DEFAULT '',
	calledstationid         varchar(64),
	callingstationid        varchar(64) NOT NULL DEFAULT '',
	expiry_time             timestamp DEFAULT NULL,
	username                varchar(100)
);
 
-- Example of how to put IPs in the pool
-- INSERT INTO radippool (id, pool_name, framedipaddress) VALUES (1, 'local', '192.168.5.10');
-- INSERT INTO radippool (id, pool_name, framedipaddress) VALUES (2, 'local', '192.168.5.11');
-- INSERT INTO radippool (id, pool_name, framedipaddress) VALUES (3, 'local', '192.168.5.12');
-- INSERT INTO radippool (id, pool_name, framedipaddress) VALUES (4, 'local', '192.168.5.13');

