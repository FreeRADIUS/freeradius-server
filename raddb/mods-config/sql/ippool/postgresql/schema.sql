--
-- Table structure for table 'radippool'
--
-- See also "procedure.sql" in this directory for additional
-- indices and a stored procedure that is much faster.
--

CREATE TABLE radippool (
	id			BIGSERIAL PRIMARY KEY,
	pool_name		text NOT NULL,
	FramedIPAddress		INET NOT NULL,
	NASIPAddress		text NOT NULL default '',
	pool_key		text NOT NULL default '',
	CalledStationId		text NOT NULL default '',
	CallingStationId	text NOT NULL default ''::text,
	expiry_time		TIMESTAMP(0) without time zone NOT NULL default NOW(),
	username		text DEFAULT ''::text
);

CREATE INDEX radippool_poolname_expire ON radippool USING btree (pool_name, expiry_time);
CREATE INDEX radippool_framedipaddress ON radippool USING btree (framedipaddress);
CREATE INDEX radippool_nasip_poolkey_ipaddress ON radippool USING btree (nasipaddress, pool_key, framedipaddress);
