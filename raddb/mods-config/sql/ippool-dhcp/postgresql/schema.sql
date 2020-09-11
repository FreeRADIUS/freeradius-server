--
-- Table structure for table 'dhcpippool'
--
-- See also "procedure.sql" in this directory for
-- a stored procedure that gives much faster response.
--

CREATE TYPE dhcp_status AS ENUM ('dynamic', 'static', 'declined', 'disabled');

CREATE TABLE dhcpippool (
	id			BIGSERIAL PRIMARY KEY,
	pool_name		varchar(64) NOT NULL,
	FramedIPAddress		INET NOT NULL,
	pool_key		VARCHAR(64) NOT NULL default '0',
	gateway			VARCHAR(16) NOT NULL default '',
	expiry_time		TIMESTAMP(0) without time zone NOT NULL default NOW(),
	status			dhcp_status DEFAULT 'dynamic',
	counter			INT NOT NULL default 0
);

CREATE INDEX dhcpippool_poolname_expire ON dhcpippool USING btree (pool_name, expiry_time);
CREATE INDEX dhcpippool_framedipaddress ON dhcpippool USING btree (framedipaddress);
CREATE INDEX dhcpippool_poolname_poolkey_ipaddress ON dhcpippool USING btree (pool_name, pool_key, framedipaddress);
