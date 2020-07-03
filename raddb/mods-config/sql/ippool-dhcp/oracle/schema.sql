CREATE SEQUENCE radippool_seq START WITH 1 INCREMENT BY 1;

CREATE TABLE radippool (
	id                      INT DEFAULT ON NULL radippool_seq.NEXTVAL PRIMARY KEY,
	pool_name               VARCHAR(30) NOT NULL,
	framedipaddress         VARCHAR(15) NOT NULL,
	nasipaddress            VARCHAR(15) DEFAULT '',
	pool_key                VARCHAR(30) DEFAULT '',
	CalledStationId         VARCHAR(64) DEFAULT '',
	CallingStationId        VARCHAR(64) DEFAULT '',
	expiry_time             timestamp(0) DEFAULT CURRENT_TIMESTAMP,
	username                VARCHAR(64) DEFAULT ''
);

CREATE INDEX radippool_poolname_expire ON radippool (pool_name, expiry_time);
CREATE INDEX radippool_framedipaddress ON radippool (framedipaddress);
CREATE INDEX radippool_poolname_poolkey_ipaddress ON radippool (pool_name, pool_key, framedipaddress);

