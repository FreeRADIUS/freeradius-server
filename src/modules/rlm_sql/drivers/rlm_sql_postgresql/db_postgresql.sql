/*
 * --- David Nicklay [ Wed Nov  3 23:18:46 EST 1999 ]
 */

/*
 * - Postgres wants C style comments.
 * - not sure how to do sequences without using SERIAL
 *   (i.e. these below are limited to int4 right now)
 *   numeric(10) doesn't seem to work for sequences...
 *   haven't tried int8 yet as a sequence type yet
 * - datetimeOS DEFAULT '0000-00-00 00:00:00' should be
 *   DEFAULT now() in postgres
 * - postgres apparently creates an index for each
 *   column specified as UNIQUE 
 *   Consider implicit creation of <tablename_id_seq> for each SERIAL field!
 */



/*
 * Table structure for table 'dictionary'
 */
CREATE TABLE dictionary (
  id SERIAL,
  Type VARCHAR(30),
  Attribute VARCHAR(32),
  Value VARCHAR(32),
  Format VARCHAR(20),
  Vendor VARCHAR(32),
  PRIMARY KEY (id)
);

/*
 * Table structure for table 'nas'
 */
CREATE TABLE nas (
  id SERIAL,
  nasname VARCHAR(128),
  shortname VARCHAR(32),
  ipaddr VARCHAR(15),
  type VARCHAR(30),
  ports int4,
  secret VARCHAR(60),
  community VARCHAR(50),
  snmp VARCHAR(10),
  PRIMARY KEY (id)
);

/*
 * Table structure for table 'radacct'
 */
CREATE TABLE radacct (
  RadAcctId SERIAL,
  AcctSessionId VARCHAR(32) DEFAULT '' NOT NULL,
  AcctUniqueId VARCHAR(32) DEFAULT '' NOT NULL,
  UserName VARCHAR(32) DEFAULT '' NOT NULL,
  Realm VARCHAR(30) DEFAULT '',
  NASIPAddress VARCHAR(15) DEFAULT '' NOT NULL,
  NASPortId NUMERIC(12),
  NASPortType VARCHAR(32),
  AcctStartTime datetime,
  AcctStopTime datetime,
  AcctSessionTime NUMERIC(12),
  AcctAuthentic VARCHAR(32),
  ConnectInfo_start VARCHAR(32),
  ConnectInfo_stop VARCHAR(32),
  AcctInputOctets NUMERIC(12),
  AcctOutputOctets NUMERIC(12),
  CalledStationId VARCHAR(30) DEFAULT '' NOT NULL,
  CallingStationId VARCHAR(30) DEFAULT '' NOT NULL,
  AcctTerminateCause VARCHAR(32) DEFAULT '' NOT NULL,
  ServiceType VARCHAR(32),
  FramedProtocol VARCHAR(32),
  FramedIPAddress VARCHAR(15) DEFAULT '' NOT NULL,
  AcctStartDelay NUMERIC(12),
  AcctStopDelay NUMERIC(12),
  PRIMARY KEY (RadAcctId)
);
create index radacct_UserName on radacct (UserName);
create index radacct_AcctSessionId on radacct (AcctSessionId);
create index radacct_AcctUniqueId on radacct (AcctUniqueId);
create index radacct_FramedIPAddress on radacct (FramedIPAddress);
create index radacct_NASIPAddress on radacct (NASIPAddress);
create index radacct_AcctStartTime on radacct (AcctStartTime);
create index radacct_AcctStopTime on radacct (AcctStopTime);

/*
 * Table structure for table 'radcheck'
 */
CREATE TABLE radcheck (
  id SERIAL,
  UserName VARCHAR(30) DEFAULT '' NOT NULL,
  Attribute VARCHAR(30),
  op VARCHAR(2) NOT NULL,
  Value VARCHAR(40),
  PRIMARY KEY (id)
);
create index radcheck_UserName on radcheck (UserName,Attribute);

/*
 * Table structure for table 'radgroupcheck'
 */
CREATE TABLE radgroupcheck (
  id SERIAL,
  GroupName VARCHAR(20) DEFAULT '' NOT NULL,
  Attribute VARCHAR(40),
  op VARCHAR(2) NOT NULL,
  Value VARCHAR(40),
  PRIMARY KEY (id)
);
create index radgroupcheck_GroupName on radgroupcheck (GroupName,Attribute);

/*
 * Table structure for table 'radgroupreply'
 */
CREATE TABLE radgroupreply (
  id SERIAL,
  GroupName VARCHAR(20) DEFAULT '' NOT NULL,
  Attribute VARCHAR(40),
  op VARCHAR(2) NOT NULL,
  Value VARCHAR(40),
  PRIMARY KEY (id)
);
create index radgroupreply_GroupName on radgroupreply (GroupName,Attribute);

/*
 * Table structure for table 'radreply'
 */
CREATE TABLE radreply (
  id SERIAL,
  UserName VARCHAR(30) DEFAULT '' NOT NULL,
  Attribute VARCHAR(30),
  op VARCHAR(2) NOT NULL,
  Value VARCHAR(40),
  PRIMARY KEY (id)
);
create index radreply_UserName on radreply (UserName,Attribute);

/*
 * Table structure for table 'usergroup'
 */
CREATE TABLE usergroup (
  id SERIAL,
  UserName VARCHAR(30) DEFAULT '' NOT NULL,
  GroupName VARCHAR(30),
  PRIMARY KEY (id)
);
create index usergroup_UserName on usergroup (UserName);

/*
 * Table structure for table 'realmgroup'
 */
CREATE TABLE realmgroup (
  id SERIAL,
  RealmName VARCHAR(30) DEFAULT '' NOT NULL,
  GroupName VARCHAR(30),
  PRIMARY KEY (id)
);
create index realmgroup_RealmName on realmgroup (RealmName);

CREATE TABLE realms (
  id SERIAL,
  realmname VARCHAR(64),
  nas VARCHAR(128),
  authport int4,
  options VARCHAR(128) DEFAULT '',
  PRIMARY KEY (id)
);


