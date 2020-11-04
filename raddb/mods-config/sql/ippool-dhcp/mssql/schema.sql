--
-- Table structure for table 'fr_ippool'
--
-- See also "procedure.sql" in this directory for
-- a stored procedure that gives much faster response.
--

CREATE TABLE fr_ippool_status (
	status_id	int NOT NULL,
	status		varchar(10) NOT NULL,
	PRIMARY KEY (status_id)
)
GO

INSERT INTO fr_ippool_status (status_id, status) VALUES (1, 'dynamic'), (2, 'static'), (3, 'declined'), (4, 'disabled')
GO

CREATE TABLE fr_ippool (
	id			int IDENTITY (1,1) NOT NULL,
	pool_name		varchar(30) NOT NULL,
	address		varchar(15) NOT NULL default '',
	pool_key		varchar(30) NOT NULL default '',
	gateway			varchar(15) NOT NULL default '',
	expiry_time		DATETIME NOT NULL default CURRENT_TIMESTAMP,
	status_id		int NOT NULL default 1,
	counter			int NOT NULL default 0,
	CONSTRAINT fk_status_id FOREIGN KEY (status_id) REFERENCES fr_ippool_status (status_id),
	PRIMARY KEY (id)
)
GO

CREATE INDEX dhcp_poolname_expire ON fr_ippool(pool_name, expiry_time)
GO

CREATE INDEX dhcp_address ON fr_ippool(address)
GO

CREATE INDEX dhcp_poolname_poolkey_address ON fr_ippool(pool_name, pool_key, address)
GO

