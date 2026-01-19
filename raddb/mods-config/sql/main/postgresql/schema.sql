--
-- $Id$
--
-- Postgresql schema for FreeRADIUS
--

--
-- Table structure for table 'radacct'
--
CREATE TABLE IF NOT EXISTS radacct (
	radacctid		bigserial PRIMARY KEY,
	acctsessionid		text NOT NULL,
	acctuniqueid		text NOT NULL UNIQUE,
	username		text,
	groupname		text,
	realm			text,
	nasipaddress		inet NOT NULL,
	nasportid		text,
	nasporttype		text,
	acctstarttime		timestamp with time zone,
	acctupdatetime		timestamp with time zone,
	acctstoptime		timestamp with time zone,
	acctinterval		bigint,
	acctsessiontime		bigint,
	acctauthentic		text,
	connectinfo_start	text,
	connectinfo_stop	text,
	acctinputoctets		bigint,
	acctoutputoctets	bigint,
	calledstationid		text,
	callingstationid	text,
	acctterminatecause	text,
	servicetype		text,
	framedprotocol		text,
	framedipaddress		inet,
	framedipv6address	inet,
	framedipv6prefix	inet,
	framedinterfaceid	text,
	delegatedipv6prefix	inet,
	class 			text
);
-- This index may be useful..
-- CREATE UNIQUE INDEX radacct_whoson on radacct (AcctStartTime, nasipaddress);

-- For use by update-, stop- and simul_* queries
CREATE INDEX radacct_active_session_idx ON radacct (acctuniqueid) WHERE acctstoptime IS NULL;

-- Add if you you regularly have to replay packets
-- CREATE INDEX radacct_session_idx ON radacct (AcctUniqueId);

-- For use by onoff-
CREATE INDEX radacct_bulk_close ON radacct (nasipaddress, acctstarttime) WHERE acctstoptime IS NULL;

-- For use by cleanup scripts
-- Works well for timeout queries, where ((acctstoptime IS NULL) AND (acctupdatetime < (now() - '1 day'::interval)))
-- as well as removing old sessions from the database.
--
-- Although at first glance it appears where an index on acctupdatetime with condition WHERE acctstoptime IS NULL;
-- would be more effective, the query planner refused to use the index (for some unknown reason), and doing it this
-- way allows the index to be used for both timeouts and cleanup.
CREATE INDEX radacct_bulk_timeout ON radacct (acctstoptime NULLS FIRST, acctupdatetime);

-- and for common statistic queries:
CREATE INDEX radacct_start_user_idx ON radacct (acctstarttime, username);
-- and, optionally
-- CREATE INDEX radacct_stop_user_idx ON radacct (acctstoptime, username);

--
-- Table structure for table 'radcheck'
--
CREATE TABLE radcheck (
	id			serial PRIMARY KEY,
	username		text NOT NULL DEFAULT '',
	attribute		text NOT NULL DEFAULT '',
	op			VARCHAR(2) NOT NULL DEFAULT '==',
	value			text NOT NULL DEFAULT ''
);
create index radcheck_username on radcheck (username,attribute);
--
-- Use this index if you use case insensitive queries
--
-- create index radcheck_username_lower on radcheck (lower(username),attribute);

--
-- Table structure for table 'radgroupcheck'
--
CREATE TABLE radgroupcheck (
	id			serial PRIMARY KEY,
	groupname		text NOT NULL DEFAULT '',
	attribute		text NOT NULL DEFAULT '',
	op			VARCHAR(2) NOT NULL DEFAULT '==',
	value			text NOT NULL DEFAULT ''
);
create index radgroupcheck_groupname on radgroupcheck (groupname,attribute);

--
-- Table structure for table 'radgroupreply'
--
CREATE TABLE radgroupreply (
	id			serial PRIMARY KEY,
	groupname		text NOT NULL DEFAULT '',
	attribute		text NOT NULL DEFAULT '',
	op			VARCHAR(2) NOT NULL DEFAULT '=',
	value			text NOT NULL DEFAULT ''
);
create index radgroupreply_groupname on radgroupreply (groupname,attribute);

--
-- Table structure for table 'radreply'
--
CREATE TABLE radreply (
	id			serial PRIMARY KEY,
	username		text NOT NULL DEFAULT '',
	attribute		text NOT NULL DEFAULT '',
	op			VARCHAR(2) NOT NULL DEFAULT '=',
	value			text NOT NULL DEFAULT ''
);
create index radreply_username on radreply (username,attribute);
--
-- Use this index if you use case insensitive queries
--
-- create index radreply_username_lower on radreply (lower(username),attribute);

--
-- Table structure for table 'radusergroup'
--
CREATE TABLE radusergroup (
	id			serial PRIMARY KEY,
	username		text NOT NULL DEFAULT '',
	groupname		text NOT NULL DEFAULT '',
	priority		integer NOT NULL DEFAULT 0
);
create index radusergroup_username on radusergroup (UserName);
--
-- Use this index if you use case insensitive queries
--
-- create index radusergroup_username_lower on radusergroup (lower(username));

--
-- Table structure for table 'radpostauth'
--
CREATE TABLE radpostauth (
	id			bigserial PRIMARY KEY,
	username		text NOT NULL,
	pass			text,
	reply			text,
	calledstationid		text,
	callingstationid	text,
	authdate		timestamp with time zone NOT NULL default now(),
	class			text
);

--
-- Table structure for table 'nas'
--
CREATE TABLE nas (
	id			serial PRIMARY KEY,
	nasname			text NOT NULL,
	shortname		text NOT NULL,
	type			text NOT NULL DEFAULT 'other',
	ports			integer,
	secret			text NOT NULL,
	server			text,
	community		text,
	description		text,
	require_ma		text NOT NULL DEFAULT 'auto',
	limit_proxy_state	text NOT NULL DEFAULT 'auto'
);
create index nas_nasname on nas (nasname);

/*
 * Table structure for table 'nasreload'
 */
CREATE TABLE IF NOT EXISTS nasreload (
	nasipaddress		inet PRIMARY KEY,
	reloadtime		timestamp with time zone NOT NULL
);
