--
-- Table structure for table 'fr_ippool'
--
-- See also "procedure.sql" in this directory for
-- a stored procedure that can give faster response.
--

CREATE TYPE dhcp_status AS ENUM ('dynamic', 'static', 'declined', 'disabled');

CREATE TABLE fr_ippool (
	id			BIGSERIAL PRIMARY KEY,
	pool_name		varchar(64) NOT NULL,
	address		INET NOT NULL,
	pool_key		VARCHAR(64) NOT NULL default '0',
	gateway			VARCHAR(16) NOT NULL default '',
	expiry_time		TIMESTAMP(0) without time zone NOT NULL default NOW(),
	status			dhcp_status DEFAULT 'dynamic',
	counter			INT NOT NULL DEFAULT 0
);

CREATE INDEX fr_ippool_poolname_expire ON fr_ippool USING btree (pool_name, expiry_time);
CREATE INDEX fr_ippool_address ON fr_ippool USING btree (address);
CREATE INDEX fr_ippool_poolname_poolkey_ipaddress ON fr_ippool USING btree (pool_name, pool_key, address);
