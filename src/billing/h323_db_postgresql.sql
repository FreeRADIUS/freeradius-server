/*
 * --- Peter Nixon [ codemonkey@peternixon.net ]
 * This is a custom SQL schema for doing H323 VoIP accounting with FreeRadius and
 * Cisco gateways (I am using 5300 and 5350 series). 
 * I will scale ALOT better than the default radius schema which is designed for
 * simple dialup installations of FreeRadius.
 * It must have custom SQL queries in raddb/postgresql.conf to work.
 *
 */

/*
 * Function 'strip_dot'
 * removes "." from the start of time fields (Cisco devices that have lost ntp timesync temporarily)
 *  * Used as:
 *      insert into mytable values (strip_dot('.16:46:02.356 EET Wed Dec 11 2002'));
 *
 * Note: On SuSE Linux 8.0 and 8.0 you need to do the following from the command line before
 *       plperl functions will work.
 *
 * # ln -s /usr/lib/perl5/5.8.0/i586-linux-thread-multi/CORE/libperl.so /usr/lib/libperl.so
 * # createlang -U postgres plperl radius
 */

CREATE OR REPLACE function strip_dot (text) returns timestamp as '
        my $datetime = $_[0];
	$datetime =~ s/^\\.*//;
        return $datetime;
' language 'plperl';


/*
 * Table structure for table 'dictionary'
 */
CREATE OR REPLACE TABLE dictionary (
  id SERIAL,
  Type VARCHAR(30),
  Attribute VARCHAR(32),
  Value VARCHAR(32),
  Format VARCHAR(20),
  Vendor VARCHAR(32),
  PRIMARY KEY (id)
)

/*
 * Table structure for table 'nas'
 */
CREATE OR REPLACE TABLE nas (
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
 * Table structure for table 'radacctstart'
 */

CREATE OR REPLACE TABLE radacctstart (
  RadAcctId SERIAL,
  AcctSessionId VARCHAR(32) DEFAULT '' NOT NULL,
  AcctUniqueId VARCHAR(32) DEFAULT '' NOT NULL,
  UserName VARCHAR(64) DEFAULT '' NOT NULL,
  Realm VARCHAR(64) DEFAULT '',
  NASIPAddress VARCHAR(15) DEFAULT '' NOT NULL,
  NASPortType VARCHAR(32),
  AcctStartTime timestamp DEFAULT now() NOT NULL,
  ConnectInfo_start VARCHAR(32),
  CalledStationId VARCHAR(30) DEFAULT '' NOT NULL,
  CallingStationId VARCHAR(15) DEFAULT '' NOT NULL,
  ServiceType VARCHAR(32),
  FramedIPAddress VARCHAR(15) DEFAULT '' NOT NULL,
  AcctStartDelay NUMERIC(12),
  AcctStatusType varchar(16) DEFAULT '' NOT NULL,
  H323GWID varchar(32) DEFAULT '' NOT NULL,
  h323CallOrigin varchar(64) DEFAULT '' NOT NULL,
  h323CallType varchar(64) DEFAULT '' NOT NULL,
  h323SetupTime timestamp with time zone DEFAULT now() NOT NULL,
  h323ConfID varchar(64) DEFAULT '' NOT NULL,
  RadiusServerName varchar(32) DEFAULT '' NOT NULL,
  PRIMARY KEY (RadAcctId)
);
create index radacctstart_UserName on radacctstart (UserName);
create index radacctstart_AcctSessionId on radacctstart (AcctSessionId);
create index radacctstart_AcctUniqueId on radacctstart (AcctUniqueId);
create index radacctstart_FramedIPAddress on radacctstart (FramedIPAddress);
create index radacctstart_NASIPAddress on radacctstart (NASIPAddress);
create index radacctstart_h323SetupTime on radacctstart (h323SetupTime);


/*
 * Table structure for 'radacct' tables
 */
CREATE OR REPLACE TABLE StopVoIP (
  RadAcctId SERIAL,
  AcctSessionId VARCHAR(32) DEFAULT '' NOT NULL,
  AcctUniqueId VARCHAR(32) DEFAULT '' NOT NULL,
  UserName VARCHAR(64) DEFAULT '' NOT NULL,
  Realm VARCHAR(64) DEFAULT '',
  NASIPAddress VARCHAR(15) DEFAULT '' NOT NULL,
  NASPortId NUMERIC(12),
  NASPortType VARCHAR(32),
  AcctStartTime timestamp DEFAULT now() NOT NULL,
  AcctStopTime timestamp DEFAULT now() NOT NULL,
  AcctSessionTime NUMERIC(12),
  AcctAuthentic VARCHAR(32),
  ConnectInfo_start VARCHAR(32),
  ConnectInfo_stop VARCHAR(32),
  AcctInputOctets NUMERIC(12),
  AcctOutputOctets NUMERIC(12),
  CalledStationId VARCHAR(30) DEFAULT '' NOT NULL,
  CallingStationId VARCHAR(15) DEFAULT '' NOT NULL,
  AcctTerminateCause VARCHAR(32) DEFAULT '' NOT NULL,
  ServiceType VARCHAR(32),
  FramedProtocol VARCHAR(32),
  FramedIPAddress VARCHAR(15) DEFAULT '' NOT NULL,
  AcctStartDelay NUMERIC(12),
  AcctStopDelay NUMERIC(12),
  AcctStatusType varchar(16) DEFAULT '' NOT NULL,
  CiscoNASPort varchar(16) DEFAULT '' NOT NULL,
  H323GWID varchar(32) DEFAULT '' NOT NULL,
  h323CallOrigin varchar(64) DEFAULT '' NOT NULL,
  h323CallType varchar(64) DEFAULT '' NOT NULL,
  h323SetupTime timestamp with time zone DEFAULT now() NOT NULL,
  h323ConnectTime timestamp with time zone DEFAULT now() NOT NULL,
  h323DisconnectTime timestamp with time zone DEFAULT now() NOT NULL,
  h323DisconnectCause varchar(32) DEFAULT '' NOT NULL,
  H323RemoteAddress varchar(64)  DEFAULT '' NOT NULL,
  H323VoiceQuality NUMERIC(4),
  h323ConfID varchar(64) DEFAULT '' NOT NULL,
  RadiusServerName varchar(32) DEFAULT '' NOT NULL,
  PRIMARY KEY (RadAcctId)
);
create index stopvoipUserName on stopvoip (UserName);
create index stopvoipAcctSessionId on stopvoip (AcctSessionId);
create index stopvoipAcctUniqueId on stopvoip (AcctUniqueId);
create index stopvoipFramedIPAddress on stopvoip (FramedIPAddress);
create index stopvoipNASIPAddress on stopvoip (NASIPAddress);
create index stopvoiph323ConnectTime on stopvoip (h323ConnectTime);
create index stopvoiph323DisconnectTime on stopvoip (h323DisconnectTime);
create index stopvoipAcctSessionTime on stopvoip (AcctSessionTime);
create index stopvoiph323remoteaddress on stopvoip (h323remoteaddress);
create index stopvoiph323ConfID on stopvoip (h323ConfID);

CREATE OR REPLACE TABLE StopTelephony (
  RadAcctId SERIAL,
  AcctSessionId VARCHAR(32) DEFAULT '' NOT NULL,
  AcctUniqueId VARCHAR(32) DEFAULT '' NOT NULL,
  UserName VARCHAR(64) DEFAULT '' NOT NULL,
  Realm VARCHAR(64) DEFAULT '',
  NASIPAddress VARCHAR(15) DEFAULT '' NOT NULL,
  NASPortId NUMERIC(12),
  NASPortType VARCHAR(32),
  AcctStartTime timestamp DEFAULT now() NOT NULL,
  AcctStopTime timestamp DEFAULT now() NOT NULL,
  AcctSessionTime NUMERIC(12),
  AcctAuthentic VARCHAR(32),
  ConnectInfo_start VARCHAR(32),
  ConnectInfo_stop VARCHAR(32),
  AcctInputOctets NUMERIC(12),
  AcctOutputOctets NUMERIC(12),
  CalledStationId VARCHAR(30) DEFAULT '' NOT NULL,
  CallingStationId VARCHAR(15) DEFAULT '' NOT NULL,
  AcctTerminateCause VARCHAR(32) DEFAULT '' NOT NULL,
  ServiceType VARCHAR(32),
  FramedProtocol VARCHAR(32),
  FramedIPAddress VARCHAR(15) DEFAULT '' NOT NULL,
  AcctStartDelay NUMERIC(12),
  AcctStopDelay NUMERIC(12),
  AcctStatusType varchar(16) DEFAULT '' NOT NULL,
  CiscoNASPort varchar(16) DEFAULT '' NOT NULL,
  H323GWID varchar(32) DEFAULT '' NOT NULL,
  h323CallOrigin varchar(64) DEFAULT '' NOT NULL,
  h323CallType varchar(64) DEFAULT '' NOT NULL,
  h323SetupTime timestamp with time zone DEFAULT now() NOT NULL,
  h323ConnectTime timestamp with time zone DEFAULT now() NOT NULL,
  h323DisconnectTime timestamp with time zone DEFAULT now() NOT NULL,
  h323DisconnectCause varchar(32) DEFAULT '' NOT NULL,
  H323RemoteAddress varchar(64)  DEFAULT '' NOT NULL,
  H323VoiceQuality NUMERIC(4),
  h323ConfID varchar(64) DEFAULT '' NOT NULL,
  RadiusServerName varchar(32) DEFAULT '' NOT NULL,
  PRIMARY KEY (RadAcctId)
);
create index StopTelephonyUserName on stoptelephony (UserName);
create index StopTelephonyAcctSessionId on stoptelephony (AcctSessionId);
create index StopTelephonyAcctUniqueId on stoptelephony (AcctUniqueId);
create index StopTelephonyFramedIPAddress on stoptelephony (FramedIPAddress);
create index StopTelephonyNASIPAddress on stoptelephony (NASIPAddress);
create index StopTelephonyh323ConnectTime on stoptelephony (h323ConnectTime);
create index StopTelephonyh323DisconnectTime on stoptelephony (h323DisconnectTime);
create index StopTelephonyAcctSessionTime on stoptelephony (AcctSessionTime);
create index StopTelephonyh323remoteaddress on stoptelephony (h323remoteaddress);


/*
 * Some sample VIEW statements
 */
CREATE VIEW call_history AS
SELECT pots.h323ConnectTime, pots.AcctSessionTime, pots.CalledStationId, ip.H323RemoteAddress, ip.NASIPAddress
FROM StopTelephony  AS pots, StopVoIP AS ip
WHERE pots.h323ConfID = ip.h323ConfID;

CREATE VIEW calls AS
SELECT h323ConnectTime, AcctSessionTime, CalledStationId, H323RemoteAddress, NASIPAddress
FROM call_history
WHERE AcctSessionTime > 0
ORDER BY h323ConnectTime, CalledStationId, AcctSessionTime, H323RemoteAddress ASC;

CREATE VIEW call_errors AS
SELECT h323SetupTime, h323disconnectcause, AcctSessionTime, CalledStationId, H323RemoteAddress
FROM StopVoIP
WHERE h323disconnectcause <> 0 AND h323disconnectcause <> 10
AND h323disconnectcause <> 11 AND h323disconnectcause <> 13
ORDER BY h323SetupTime, CalledStationId, H323RemoteAddress ASC;

CREATE VIEW call_history_daily AS
SELECT pots.h323ConnectTime, pots.AcctSessionTime, pots.CalledStationId, ip.H323RemoteAddress, pots.NASIPAddress
FROM StopTelephony AS pots, StopVoIP AS ip
WHERE pots.h323connecttime BETWEEN DATE'YESTERDAY' AND DATE'TODAY' AND pots.h323ConfID = ip.h323ConfID
ORDER BY h323ConnectTime, CalledStationId ASC;

CREATE VIEW call_errors AS
SELECT pots.h323ConnectTime, pots.AcctSessionTime, pots.CalledStationId, ip.H323RemoteAddress, pots.NASIPAddress
FROM StopTelephony  AS pots, StopVoIP AS ip
WHERE pots.h323ConfID = ip.h323ConfID AND ip.h323disconnectcause <> 0 AND ip.h323disconnectcause <> 10
AND ip.h323disconnectcause <> 11 AND ip.h323disconnectcause <> 13
ORDER BY h323ConnectTime, CalledStationId, H323RemoteAddress ASC;

/*
 * Table structure for table 'radcheck'
 */
CREATE TABLE radcheck (
  id SERIAL,
  UserName VARCHAR(30) DEFAULT '' NOT NULL,
  Attribute VARCHAR(30),
  Value VARCHAR(40),
  op VARCHAR(2),
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
  Value VARCHAR(40),
  op VARCHAR(2),
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
  Value VARCHAR(40),
  op VARCHAR(2),
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
  Value VARCHAR(40),
  op VARCHAR(2),
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


