CREATE TABLE dhcpstatus (
	status_id		INT PRIMARY KEY,
	status			VARCHAR(10) NOT NULL
);

INSERT INTO dhcpstatus (status_id, status) VALUES (1, 'dynamic');
INSERT INTO dhcpstatus (status_id, status) VALUES (2, 'static');
INSERT INTO dhcpstatus (status_id, status) VALUES (3, 'declined');
INSERT INTO dhcpstatus (status_id, status) VALUES (4, 'disabled');

CREATE SEQUENCE dhcpippool_seq START WITH 1 INCREMENT BY 1;

CREATE TABLE dhcpippool (
	id			INT DEFAULT ON NULL dhcpippool_seq.NEXTVAL PRIMARY KEY,
	pool_name		VARCHAR(30) NOT NULL,
	framedipaddress		VARCHAR(15) NOT NULL,
	pool_key		VARCHAR(30) NOT NULL,
	gateway			VARCHAR(15) NOT NULL,
	expiry_time		TIMESTAMP(0) NOT NULL,
	status_id		INT DEFAULT 1,
	FOREIGN KEY (status_id) REFERENCES dhcpstatus(status_id)
);

CREATE INDEX dhcpippool_poolname_expire ON dhcpippool (pool_name, expiry_time);
CREATE INDEX dhcpippool_framedipaddress ON dhcpippool (framedipaddress);
CREATE INDEX dhcpippool_poolname_poolkey ON dhcpippool (pool_name, pool_key, framedipaddress);

