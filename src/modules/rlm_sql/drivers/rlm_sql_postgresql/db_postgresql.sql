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
 * Note: Column type BIGSERIAL does not exist prior to Postgres 7.2
 *       If you run an older version you need to change this to SERIAL
 */
CREATE TABLE radacct (
	RadAcctId		BIGSERIAL PRIMARY KEY,
	AcctSessionId		VARCHAR(32) NOT NULL,
	AcctUniqueId		VARCHAR(32) NOT NULL,
	UserName		VARCHAR(32),
	Realm			VARCHAR(30),
	NASIPAddress		INET NOT NULL,
	NASPortId		INTEGER,
	NASPortType		VARCHAR(32),
	AcctStartTime		TIMESTAMP with time zone,
	AcctStopTime		TIMESTAMP with time zone,
	AcctSessionTime		BIGINT,
	AcctAuthentic		VARCHAR(32),
	ConnectInfo_start	VARCHAR(32),
	ConnectInfo_stop	VARCHAR(32),
	AcctInputOctets		BIGINT,
	AcctOutputOctets	BIGINT,
	CalledStationId		VARCHAR(50),
	CallingStationId	VARCHAR(50),
	AcctTerminateCause	VARCHAR(32),
	ServiceType		VARCHAR(32),
	FramedProtocol		VARCHAR(32),
	FramedIPAddress		INET,
	AcctStartDelay		BIGINT,
	AcctStopDelay		BIGINT
);
-- This index may be usefull..
-- CREATE UNIQUE INDEX radacct_whoson on radacct (AcctStartTime, nasipaddress);

-- For use by onoff-, update-, stop- and simul_* queries
CREATE INDEX radacct_active_user_idx ON radacct (userName) WHERE AcctStopTime IS NULL;
-- and for common statistic queries:
CREATE INDEX radacct_start_user_idx ON radacct (acctStartTime, UserName);
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
	id		SERIAL PRIMARY KEY,
	UserName	VARCHAR(30) DEFAULT '' NOT NULL,
	Attribute	VARCHAR(30),
	op VARCHAR(2)	NOT NULL DEFAULT '==',
	Value		VARCHAR(40)
);
create index radcheck_UserName on radcheck (UserName,Attribute);

/*
 * Table structure for table 'radgroupcheck'
 */
CREATE TABLE radgroupcheck (
	id		SERIAL PRIMARY KEY,
	GroupName	VARCHAR(20) DEFAULT '' NOT NULL,
	Attribute	VARCHAR(40),
	op		VARCHAR(2) NOT NULL DEFAULT '==',
	Value		VARCHAR(40)
);
create index radgroupcheck_GroupName on radgroupcheck (GroupName,Attribute);

/*
 * Table structure for table 'radgroupreply'
 */
CREATE TABLE radgroupreply (
	id		SERIAL PRIMARY KEY,
	GroupName	VARCHAR(20) DEFAULT '' NOT NULL,
	Attribute	VARCHAR(40),
	op		VARCHAR(2) NOT NULL DEFAULT '=',
	Value		VARCHAR(40)
);
create index radgroupreply_GroupName on radgroupreply (GroupName,Attribute);

/*
 * Table structure for table 'radreply'
 */
CREATE TABLE radreply (
	id		SERIAL PRIMARY KEY,
	UserName	VARCHAR(30) DEFAULT '' NOT NULL,
	Attribute	VARCHAR(30),
	op		VARCHAR(2) NOT NULL DEFAULT '=',
	Value		VARCHAR(40)
);
create index radreply_UserName on radreply (UserName,Attribute);

/*
 * Table structure for table 'usergroup'
 */
CREATE TABLE usergroup (
	id		SERIAL PRIMARY KEY,
	UserName	VARCHAR(30) DEFAULT '' NOT NULL,
	GroupName	VARCHAR(30)
);
create index usergroup_UserName on usergroup (UserName);

/*
 * Table structure for table 'realmgroup'
 */
CREATE TABLE realmgroup (
	id		SERIAL PRIMARY KEY,
	RealmName	VARCHAR(30) DEFAULT '' NOT NULL,
	GroupName	VARCHAR(30)
);
create index realmgroup_RealmName on realmgroup (RealmName);

/*
 * Table structure for table 'realms'
 * This is not yet used by FreeRADIUS 
 */
CREATE TABLE realms (
	id		SERIAL PRIMARY KEY,
	realmname	VARCHAR(64),
	nas		VARCHAR(128),
	authport	int4,
	options		VARCHAR(128) DEFAULT ''
);

/*
 * Table structure for table 'nas'
 */
CREATE TABLE nas (
	id		SERIAL PRIMARY KEY,
	nasname		VARCHAR(128) NOT NULL,
	shortname	VARCHAR(32) NOT NULL,
	type		VARCHAR(30) NOT NULL DEFAULT 'other',
	ports		int4,
	secret		VARCHAR(60) NOT NULL,
	community	VARCHAR(50),
	description	VARCHAR(200)
);
create index nas_nasname on nas (nasname);

--
-- Table structure for table 'radpostauth'
--

CREATE TABLE radpostauth (
	id		BIGSERIAL PRIMARY KEY,
	username	VARCHAR(64) NOT NULL,
	pass		VARCHAR(64),
	reply		VARCHAR(32),
	authdate	TIMESTAMP with time zone NOT NULL default 'now'
) ;

--
-- Table structure for table 'dictionary'
-- This is not currently used by FreeRADIUS
--
-- CREATE TABLE dictionary (
--     id              SERIAL PRIMARY KEY,
--     Type            VARCHAR(30),
--     Attribute       VARCHAR(64),
--     Value           VARCHAR(64),
--     Format          VARCHAR(20),
--     Vendor          VARCHAR(32)
-- );

/*
 * Note: (pnixon: 2003-12-10) The following function should not be required
 * if you use the PG specific queries in raddb/postgresql.conf
 *
 * Common utility function for date calculations. This is used in our
 * alternative account stop query to calculate the start of a session.
 *
 * This function is Copyright 2001 by Mark Steele (msteele@inet-interactif.com)
 *
 * Please note that this requires the plpgsql to be available in your
 * radius database. If it is not available you can register it with
 * postgres by running this command:
 *
 *   createlang plpgsql <databasename>
 */
CREATE FUNCTION DATE_SUB(date,int4,text) RETURNS DATE AS '
DECLARE
        var1 date;
        var2 text;
BEGIN
        var2 = $2 || '' '' || $3;
        SELECT INTO var1
                to_date($1 - var2::interval, ''YYYY-MM-DD'');
RETURN var1;
END;' LANGUAGE 'plpgsql';
