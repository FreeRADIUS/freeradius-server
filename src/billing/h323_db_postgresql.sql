/*
 * --- Peter Nixon [ codemonkey@peternixon.net ]
 * This is a custom SQL schema for doing H323 VoIP accounting with FreeRadius and
 * Cisco gateways (I am using 5300 and 5350 series). 
 * It will scale ALOT better than the default radius schema which is designed for
 * simple dialup installations of FreeRadius.
 * It must have custom SQL queries in raddb/postgresql.conf to work.
 *
 * If you wish to do RADIUS Authentication using the same database, you must use
 * src/modules/rlm_sql/drivers/rlm_sql_postgresql/db_postgresql.sql as well as
 * this schema.
 *
 */

/*
 * Table structure for 'Start' tables
 */

CREATE TABLE StartVoIP (
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
  AcctStatusType VARCHAR(16) DEFAULT '' NOT NULL,
  H323GWID VARCHAR(32) DEFAULT '' NOT NULL,
  h323CallOrigin VARCHAR(64) DEFAULT '' NOT NULL,
  h323CallType VARCHAR(64) DEFAULT '' NOT NULL,
  h323SetupTime timestamp with time zone DEFAULT now() NOT NULL,
  h323ConfID VARCHAR(64) DEFAULT '' NOT NULL,
  RadiusServerName VARCHAR(32) DEFAULT '' NOT NULL,
  PRIMARY KEY (RadAcctId)
);
create index startvoip_UserName on startvoip (UserName);
create index startvoip_AcctSessionId on startvoip (AcctSessionId);
create index startvoip_AcctUniqueId on startvoip (AcctUniqueId);
create index startvoip_FramedIPAddress on startvoip (FramedIPAddress);
create index startvoip_NASIPAddress on startvoip (NASIPAddress);
create index startvoip_h323SetupTime on startvoip (h323SetupTime);


CREATE TABLE StartTelephony (
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
  AcctStatusType VARCHAR(16) DEFAULT '' NOT NULL,
  H323GWID VARCHAR(32) DEFAULT '' NOT NULL,
  h323CallOrigin VARCHAR(64) DEFAULT '' NOT NULL,
  h323CallType VARCHAR(64) DEFAULT '' NOT NULL,
  h323SetupTime timestamp with time zone DEFAULT now() NOT NULL,
  h323ConfID VARCHAR(64) DEFAULT '' NOT NULL,
  RadiusServerName VARCHAR(32) DEFAULT '' NOT NULL,
  PRIMARY KEY (RadAcctId)
);
create index starttelephony_UserName on starttelephony (UserName);
create index starttelephony_AcctSessionId on starttelephony (AcctSessionId);
create index starttelephony_AcctUniqueId on starttelephony (AcctUniqueId);
create index starttelephony_FramedIPAddress on starttelephony (FramedIPAddress);
create index starttelephony_NASIPAddress on starttelephony (NASIPAddress);
create index starttelephony_h323SetupTime on starttelephony (h323SetupTime);



/*
 * Table structure for 'Stop' tables
 */
CREATE TABLE StopVoIP (
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


CREATE TABLE StopTelephony (
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

CREATE OR REPLACE FUNCTION strip_dot (text) returns timestamp AS '
        my $datetime = $_[0];
	$datetime =~ s/^\\.*//;
        return $datetime;
' language 'plperl';


/*
 * Some sample database VIEWs to simplify billing queries.
 */
CREATE OR REPLACE VIEW call_history AS
SELECT pots.h323ConnectTime, pots.AcctSessionTime, pots.CalledStationId, ip.H323RemoteAddress, ip.NASIPAddress
FROM StopTelephony  AS pots, StopVoIP AS ip
WHERE pots.h323ConfID = ip.h323ConfID;

CREATE OR REPLACE VIEW calls AS
SELECT h323ConnectTime, AcctSessionTime, CalledStationId, H323RemoteAddress, NASIPAddress
FROM call_history
WHERE AcctSessionTime > 0
ORDER BY h323ConnectTime, CalledStationId, AcctSessionTime, H323RemoteAddress ASC;

CREATE OR REPLACE VIEW call_history_daily AS
SELECT pots.h323ConnectTime, pots.AcctSessionTime, pots.CalledStationId, ip.H323RemoteAddress, pots.NASIPAddress
FROM StopTelephony AS pots, StopVoIP AS ip
WHERE pots.h323connecttime BETWEEN DATE'YESTERDAY' AND DATE'TODAY' AND pots.h323ConfID = ip.h323ConfID
ORDER BY h323ConnectTime, CalledStationId ASC;

CREATE OR REPLACE VIEW call_errors AS
SELECT pots.h323ConnectTime, pots.AcctSessionTime, pots.CalledStationId, ip.H323RemoteAddress, pots.NASIPAddress
FROM StopTelephony  AS pots, StopVoIP AS ip
WHERE pots.h323ConfID = ip.h323ConfID AND ip.h323disconnectcause <> 0 AND ip.h323disconnectcause <> 10
AND ip.h323disconnectcause <> 11 AND ip.h323disconnectcause <> 13
ORDER BY H323ConnectTime, CalledStationId, H323RemoteAddress ASC;
