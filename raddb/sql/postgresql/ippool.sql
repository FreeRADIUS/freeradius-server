--
-- Table structure for table 'radippool'
--

CREATE TABLE radippool (
	id			BIGSERIAL PRIMARY KEY,
	pool_name		varchar(64) NOT NULL,
	FramedIPAddress		INET NOT NULL,
	NASIPAddress		VARCHAR(16) NOT NULL default '',
	pool_key		VARCHAR(64) NOT NULL default 0,
	CalledStationId		VARCHAR(64),
	CallingStationId	text NOT NULL default ''::text,
	expiry_time		TIMESTAMP(0) without time zone NOT NULL default 'now'::timestamp(0),
	username		text DEFAULT ''::text
);

CREATE INDEX radippool_poolname_ipaadr ON radippool USING btree (pool_name, framedipaddress);
CREATE INDEX radippool_poolname_expire ON radippool USING btree (pool_name, expiry_time);
CREATE INDEX radippool_nasipaddr_poolkey ON radippool USING btree (nasipaddress, pool_key);
CREATE INDEX radippool_nasipaddr_calling ON radippool USING btree (nasipaddress, callingstationid);

