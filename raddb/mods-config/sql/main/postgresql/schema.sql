/*
 * $Id$
 *
 * Postgresql schema for FreeRADIUS
 *
 * All field lengths need checking as some are still suboptimal. -pnixon 2003-07-13
 *
 */

/*
 * Table structure for table 'radacct'
 *
 * Note: Column type bigserial does not exist prior to Postgres 7.2
 *       If you run an older version you need to change this to serial
 */
CREATE TABLE radacct (
	RadAcctId		bigserial PRIMARY KEY,
	AcctSessionId		text NOT NULL,
	AcctUniqueId		text NOT NULL UNIQUE,
	UserName		text,
	Realm			text,
	NASIPAddress		inet NOT NULL,
	NASPortId		text,
	NASPortType		text,
	AcctStartTime		timestamp with time zone,
	AcctUpdateTime		timestamp with time zone,
	AcctStopTime		timestamp with time zone,
	AcctInterval		bigint,
	AcctSessionTime		bigint,
	AcctAuthentic		text,
	ConnectInfo_start	text,
	ConnectInfo_stop	text,
	AcctInputOctets		bigint,
	AcctOutputOctets	bigint,
	CalledStationId		text,
	CallingStationId	text,
	AcctTerminateCause	text,
	ServiceType		text,
	FramedProtocol		text,
	FramedIPAddress		inet
);
-- This index may be useful..
-- CREATE UNIQUE INDEX radacct_whoson on radacct (AcctStartTime, nasipaddress);

-- For use by update-, stop- and simul_* queries
CREATE INDEX radacct_active_session_idx ON radacct (AcctUniqueId) WHERE AcctStopTime IS NULL;

-- Add if you you regularly have to replay packets
-- CREATE INDEX radacct_session_idx ON radacct (AcctUniqueId);

-- For backwards compatibility
-- CREATE INDEX radacct_active_user_idx ON radacct (AcctSessionId, UserName, NASIPAddress) WHERE AcctStopTime IS NULL;

-- For use by onoff-
CREATE INDEX radacct_bulk_close ON radacct (NASIPAddress, AcctStartTime) WHERE AcctStopTime IS NULL;

-- and for common statistic queries:
CREATE INDEX radacct_start_user_idx ON radacct (AcctStartTime, UserName);

-- and, optionally
-- CREATE INDEX radacct_stop_user_idx ON radacct (acctStopTime, UserName);

/*
 * There was WAAAY too many indexes previously. This combo index
 * should take care of the most common searches.
 * I have commented out all the old indexes, but left them in case
 * someone wants them. I don't recomend anywone use them all at once
 * as they will slow down your DB too much.
 *  - pnixon 2003-07-13
 */

/*
 * create index radacct_UserName on radacct (UserName);
 * create index radacct_AcctSessionId on radacct (AcctSessionId);
 * create index radacct_AcctUniqueId on radacct (AcctUniqueId);
 * create index radacct_FramedIPAddress on radacct (FramedIPAddress);
 * create index radacct_NASIPAddress on radacct (NASIPAddress);
 * create index radacct_AcctStartTime on radacct (AcctStartTime);
 * create index radacct_AcctStopTime on radacct (AcctStopTime);
*/



/*
 * Table structure for table 'radcheck'
 */
CREATE TABLE radcheck (
	id			serial PRIMARY KEY,
	UserName		text NOT NULL DEFAULT '',
	Attribute		text NOT NULL DEFAULT '',
	op			VARCHAR(2) NOT NULL DEFAULT '==',
	Value			text NOT NULL DEFAULT ''
);
create index radcheck_UserName on radcheck (UserName,Attribute);
/*
 * Use this index if you use case insensitive queries
 */
-- create index radcheck_UserName_lower on radcheck (lower(UserName),Attribute);

/*
 * Table structure for table 'radgroupcheck'
 */
CREATE TABLE radgroupcheck (
	id			serial PRIMARY KEY,
	GroupName		text NOT NULL DEFAULT '',
	Attribute		text NOT NULL DEFAULT '',
	op			VARCHAR(2) NOT NULL DEFAULT '==',
	Value			text NOT NULL DEFAULT ''
);
create index radgroupcheck_GroupName on radgroupcheck (GroupName,Attribute);

/*
 * Table structure for table 'radgroupreply'
 */
CREATE TABLE radgroupreply (
	id			serial PRIMARY KEY,
	GroupName		text NOT NULL DEFAULT '',
	Attribute		text NOT NULL DEFAULT '',
	op			VARCHAR(2) NOT NULL DEFAULT '=',
	Value			text NOT NULL DEFAULT ''
);
create index radgroupreply_GroupName on radgroupreply (GroupName,Attribute);

/*
 * Table structure for table 'radreply'
 */
CREATE TABLE radreply (
	id			serial PRIMARY KEY,
	UserName		text NOT NULL DEFAULT '',
	Attribute		text NOT NULL DEFAULT '',
	op			VARCHAR(2) NOT NULL DEFAULT '=',
	Value			text NOT NULL DEFAULT ''
);
create index radreply_UserName on radreply (UserName,Attribute);
/*
 * Use this index if you use case insensitive queries
 */
-- create index radreply_UserName_lower on radreply (lower(UserName),Attribute);

/*
 * Table structure for table 'radusergroup'
 */
CREATE TABLE radusergroup (
	id			serial PRIMARY KEY,
	UserName		text NOT NULL DEFAULT '',
	GroupName		text NOT NULL DEFAULT '',
	priority		integer NOT NULL DEFAULT 0
);
create index radusergroup_UserName on radusergroup (UserName);
/*
 * Use this index if you use case insensitive queries
 */
-- create index radusergroup_UserName_lower on radusergroup (lower(UserName));

--
-- Table structure for table 'radpostauth'
--

CREATE TABLE radpostauth (
	id			bigserial PRIMARY KEY,
	username		text NOT NULL,
	pass			text,
	reply			text,
	CalledStationId		text,
	CallingStationId	text,
	authdate		timestamp with time zone NOT NULL default now()
);

/*
 * Table structure for table 'nas'
 */
CREATE TABLE nas (
	id			serial PRIMARY KEY,
	nasname			text NOT NULL,
	shortname		text NOT NULL,
	type			text NOT NULL DEFAULT 'other',
	ports			integer,
	secret			text NOT NULL,
	server			text,
	community		text,
	description		text
);
create index nas_nasname on nas (nasname);
