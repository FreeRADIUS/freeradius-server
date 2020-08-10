CREATE SEQUENCE dhcpippool_seq START WITH 1 INCREMENT BY 1;

CREATE TABLE dhcpippool (
	id                      INT DEFAULT ON NULL dhcpippool_seq.NEXTVAL PRIMARY KEY,
	pool_name               VARCHAR(30) NOT NULL,
	framedipaddress         VARCHAR(15) NOT NULL,
	pool_key                VARCHAR(30) DEFAULT '',
	gatewayipaddress        VARCHAR(15) DEFAULT '',
	expiry_time             timestamp(0) DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX dhcpippool_poolname_expire ON dhcpippool (pool_name, expiry_time);
CREATE INDEX dhcpippool_framedipaddress ON dhcpippool (framedipaddress);
CREATE INDEX dhcpippool_poolname_poolkey_ipaddress ON dhcpippool (pool_name, pool_key, framedipaddress);

