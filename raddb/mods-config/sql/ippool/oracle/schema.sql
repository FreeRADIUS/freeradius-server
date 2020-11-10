CREATE TABLE fr_ippool_status (
	status_id		INT PRIMARY KEY,
	status			VARCHAR(10) NOT NULL
);

INSERT INTO fr_ippool_status (status_id, status) VALUES (1, 'dynamic');
INSERT INTO fr_ippool_status (status_id, status) VALUES (2, 'static');
INSERT INTO fr_ippool_status (status_id, status) VALUES (3, 'declined');
INSERT INTO fr_ippool_status (status_id, status) VALUES (4, 'disabled');

CREATE SEQUENCE fr_ippool_seq START WITH 1 INCREMENT BY 1;

CREATE TABLE fr_ippool (
	id			INT DEFAULT ON NULL fr_ippool_seq.NEXTVAL PRIMARY KEY,
	pool_name		VARCHAR(30) NOT NULL,
	address		        VARCHAR(43) NOT NULL,
	owner		        VARCHAR(128) NOT NULL,
	gateway			VARCHAR(128) NOT NULL,
	expiry_time		TIMESTAMP(0) NOT NULL,
	status_id		INT DEFAULT 1,
	counter			INT DEFAULT 0,
	FOREIGN KEY (status_id) REFERENCES fr_ippool_status(status_id)
);

CREATE INDEX fr_ippool_poolname_expire ON fr_ippool (pool_name, expiry_time);
CREATE INDEX fr_ippool_address ON fr_ippool (address);
CREATE INDEX fr_ippool_poolname_poolkey ON fr_ippool (pool_name, owner, address);

