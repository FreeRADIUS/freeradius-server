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
  RadAcctId BIGSERIAL PRIMARY KEY,
  UserName VARCHAR(64) DEFAULT '' NOT NULL,
  Realm VARCHAR(64) DEFAULT '',
  NASIPAddress INET NOT NULL,
  AcctStartTime timestamp DEFAULT now() NOT NULL,
  CalledStationId VARCHAR(30) DEFAULT '' NOT NULL,
  CallingStationId VARCHAR(15) DEFAULT '' NOT NULL,
  AcctDelayTime NUMERIC(3),
  H323GWID VARCHAR(32) DEFAULT '' NOT NULL,
  h323CallOrigin VARCHAR(10) DEFAULT '' NOT NULL,
  h323CallType VARCHAR(64) DEFAULT '' NOT NULL,
  h323SetupTime timestamp with time zone DEFAULT now() NOT NULL,
  h323ConfID VARCHAR(35) DEFAULT '' NOT NULL
);
create index startvoipcombo on startvoip (h323SetupTime, nasipaddress);


CREATE TABLE StartTelephony (
  RadAcctId BIGSERIAL PRIMARY KEY,
  UserName VARCHAR(64) DEFAULT '' NOT NULL,
  Realm VARCHAR(64) DEFAULT '',
  NASIPAddress INET NOT NULL,
  AcctStartTime timestamp DEFAULT now() NOT NULL,
  CalledStationId VARCHAR(30) DEFAULT '' NOT NULL,
  CallingStationId VARCHAR(15) DEFAULT '' NOT NULL,
  AcctDelayTime NUMERIC(3),
  H323GWID VARCHAR(32) DEFAULT '' NOT NULL,
  h323CallOrigin VARCHAR(10) DEFAULT '' NOT NULL,
  h323CallType VARCHAR(64) DEFAULT '' NOT NULL,
  h323SetupTime timestamp with time zone DEFAULT now() NOT NULL,
  h323ConfID VARCHAR(35) DEFAULT '' NOT NULL
);
create index starttelephonycombo on starttelephony (h323SetupTime, nasipaddress);



/*
 * Table structure for 'Stop' tables
 */
CREATE TABLE StopVoIP (
  RadAcctId BIGSERIAL PRIMARY KEY,
  UserName VARCHAR(32) DEFAULT '' NOT NULL,
  NASIPAddress INET NOT NULL,
  AcctSessionTime BIGINT,
  AcctInputOctets BIGINT,
  AcctOutputOctets BIGINT,
  CalledStationId VARCHAR(50) DEFAULT '' NOT NULL,
  CallingStationId VARCHAR(50) DEFAULT '' NOT NULL,
  AcctDelayTime SMALLINT,
  CiscoNASPort BOOLEAN DEFAULT false,
  h323CallOrigin varchar(10) DEFAULT '' NOT NULL,
  h323SetupTime timestamp with time zone NOT NULL,
  h323ConnectTime timestamp with time zone NOT NULL,
  h323DisconnectTime timestamp with time zone NOT NULL,
  h323DisconnectCause varchar(2) DEFAULT '' NOT NULL,
  H323RemoteAddress INET NOT NULL,
  H323VoiceQuality NUMERIC(2),
  h323ConfID VARCHAR(35) DEFAULT '' NOT NULL
);
create UNIQUE index stopvoipcombo on stopvoip (h323SetupTime, nasipaddress, h323ConfID);


CREATE TABLE StopTelephony (
  RadAcctId BIGSERIAL PRIMARY KEY,
  UserName VARCHAR(32) DEFAULT '' NOT NULL,
  NASIPAddress INET NOT NULL,
  AcctSessionTime BIGINT,
  AcctInputOctets BIGINT,
  AcctOutputOctets BIGINT,
  CalledStationId VARCHAR(50) DEFAULT '' NOT NULL,
  CallingStationId VARCHAR(50) DEFAULT '' NOT NULL,
  AcctDelayTime SMALLINT,
  CiscoNASPort varchar(16) DEFAULT '' NOT NULL,
  h323CallOrigin varchar(10) DEFAULT '' NOT NULL,
  h323SetupTime timestamp with time zone NOT NULL,
  h323ConnectTime timestamp with time zone NOT NULL,
  h323DisconnectTime timestamp with time zone NOT NULL,
  h323DisconnectCause varchar(2) DEFAULT '' NOT NULL,
  H323RemoteAddress BOOLEAN DEFAULT false,
  H323VoiceQuality NUMERIC(2),
  h323ConfID VARCHAR(35) DEFAULT '' NOT NULL
);
create UNIQUE index stoptelephonycombo on stoptelephony (h323SetupTime, nasipaddress, h323ConfID);


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


CREATE OR REPLACE FUNCTION chop_number(VARCHAR) RETURNS VARCHAR AS '
 DECLARE
     original_number ALIAS FOR $1;
     new_number VARCHAR;
 BEGIN
        new_number := split_part(original_number,''#'',2);
        IF new_number = '''' THEN
         RETURN original_number;
        ELSE RETURN new_number;
     END IF;
 END;
' LANGUAGE 'plpgsql';

CREATE OR REPLACE FUNCTION chop_number_country(VARCHAR) RETURNS VARCHAR AS '
 DECLARE
     original_number ALIAS FOR $1;
     new_number VARCHAR;
     clean_number VARCHAR;
 BEGIN
        new_number := split_part(original_number,''#'',2);
        IF new_number = '''' THEN
         clean_number := original_number;
        ELSE clean_number := new_number;
        END IF;
        IF substring(clean_number from 1 for 2) = ''00'' THEN
          RETURN substring(clean_number from 3 for 2);
        ELSIF substring(clean_number from 1 for 1) = ''0'' THEN
          RETURN '''';
        ELSE
          RETURN substring(clean_number from 1 for 2);
        END IF;
 END;
' LANGUAGE 'plpgsql';

CREATE OR REPLACE FUNCTION chop_number_city(VARCHAR) RETURNS VARCHAR AS '
 DECLARE
     original_number ALIAS FOR $1;
     new_number VARCHAR;
     clean_number VARCHAR;
 BEGIN
        new_number := split_part(original_number,''#'',2);
        IF new_number = '''' THEN
         clean_number := original_number;
        ELSE clean_number := new_number;
        END IF;
        IF substring(clean_number from 1 for 2) = ''00'' THEN
          RETURN substring(clean_number from 5 for 3);
        ELSIF substring(clean_number from 1 for 1) = ''0'' THEN
          RETURN substring(clean_number from 2 for 3);
        ELSE
          RETURN substring(clean_number from 3 for 3);
        END IF;
 END;
' LANGUAGE 'plpgsql';

CREATE OR REPLACE FUNCTION chop_number_number(VARCHAR) RETURNS VARCHAR AS '
 DECLARE
     original_number ALIAS FOR $1;
     new_number VARCHAR;
     clean_number VARCHAR;
 BEGIN
        new_number := split_part(original_number,''#'',2);
        IF new_number = '''' THEN
         clean_number := original_number;
        ELSE clean_number := new_number;
        END IF;
        IF substring(clean_number from 1 for 2) = ''00'' THEN
          RETURN substring(clean_number from 8 for 11);
        ELSIF substring(clean_number from 1 for 1) = ''0'' THEN
          RETURN substring(clean_number from 5 for 11);
        ELSE
          RETURN substring(clean_number from 6 for 11);
        END IF
 END;
' LANGUAGE 'plpgsql';

/*
 * Some sample database VIEWs to simplify billing queries.
 */

CREATE OR REPLACE VIEW call_history AS
SELECT CAST ((pots.h323SetupTime::date AT TIME ZONE 'UTC') AS date) AS Date, CAST ((pots.h323SetupTime AT TIME ZONE 'UTC') AS time without time zone) AS Time, pots.AcctSessionTime AS Length, pots.CalledStationId AS Number, ip.H323RemoteAddress AS cust_ip, ip.NASIPAddress AS gw_ip
FROM StopTelephony AS pots LEFT OUTER JOIN StopVoIP AS ip
ON (pots.h323ConfID = ip.h323ConfID);

CREATE OR REPLACE VIEW call_history_customer AS
SELECT Date, Time, Length, Number, cust_ip, gw_ip, CustomerIP.Company AS Company
FROM call_history LEFT OUTER JOIN customerip
ON (call_history.cust_ip = CustomerIP.IpAddr);

CREATE OR REPLACE VIEW customerip AS
SELECT gw.cust_gw AS IpAddr, cust.company AS Company, cust.customer AS Customer, gw.location AS Location
FROM customers  AS cust, cust_gw AS gw
WHERE cust.cust_id = gw.cust_id;

CREATE OR REPLACE VIEW VoIP AS
SELECT RadAcctId AS ID, NASIPAddress AS GWIP, AcctSessionTime AS Call_Seconds, chop_number_country(CalledStationId) AS Country, chop_number_city(CalledStationId) AS City,chop_number_number(CalledStationId) AS Number, chop_number(CalledStationId) AS Original_Number, EXTRACT(YEAR FROM (h323setuptime AT TIME ZONE 'UTC')) AS Year, EXTRACT(MONTH FROM (h323setuptime AT TIME ZONE 'UTC')) AS Month, EXTRACT(DAY FROM (h323setuptime AT TIME ZONE 'UTC')) AS Day, CAST ((h323SetupTime AT TIME ZONE 'UTC') AS time without time zone) AS Time, h323DisconnectCause AS error_code, H323RemoteAddress AS Remote_IP, h323ConfID AS ConfID
FROM StopVoIP;

CREATE OR REPLACE VIEW Telephony AS
SELECT RadAcctId AS ID, NASIPAddress AS GWIP, AcctSessionTime AS Call_Seconds, chop_number_country(CalledStationId) AS Country, chop_number_city(CalledStationId) AS City,chop_number_number(CalledStationId) AS Number, chop_number(CalledStationId) AS Original_Number, EXTRACT(YEAR FROM (h323setuptime AT TIME ZONE 'UTC')) AS Year, EXTRACT(MONTH FROM (h323setuptime AT TIME ZONE 'UTC')) AS Month, EXTRACT(DAY FROM (h323setuptime AT TIME ZONE 'UTC')) AS Day, CAST ((h323SetupTime AT TIME ZONE 'UTC') AS time without time zone) AS Time, h323DisconnectCause AS error_code, split_part(split_part(CiscoNASPort,':',1),' ',2) AS PRI, split_part(CiscoNASPort,':',3) AS PRI_channel, CiscoNASPort AS isdn_port, h323ConfID AS ConfID
FROM StopTelephony;

CREATE OR REPLACE VIEW calls AS
SELECT Date, Time, AcctSessionTime, CalledStationId, H323RemoteAddress, NASIPAddress
FROM call_history
WHERE AcctSessionTime > 0
ORDER BY Date, Time, CalledStationId, AcctSessionTime, H323RemoteAddress ASC;

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


/*
 * Table structure for 'isdn_error_codes' table
 *
 * Taken from cisco.com this data can be JOINED against h323DisconnectCause to
 * give human readable error reports.
 *
 */


CREATE TABLE isdn_error_codes (
    error_code character varying(2) PRIMARY KEY,
    desc_short character varying(90),
    desc_long text
);

/*
 * Data for 'isdn_error_codes' table
 */

INSERT INTO isdn_error_codes VALUES ('1', 'Unallocated (unassigned) number', 'The ISDN number was sent to the switch in the correct format; however, the number is not assigned to any destination equipment.');
INSERT INTO isdn_error_codes VALUES ('10', 'Normal call clearing', 'Normal call clearing has occurred.');
INSERT INTO isdn_error_codes VALUES ('11', 'User busy', 'The called system acknowledges the connection request but is unable to accept the call because all B channels are in use.');
INSERT INTO isdn_error_codes VALUES ('12', 'No user responding', 'The connection cannot be completed because the destination does not respond to the call.');
INSERT INTO isdn_error_codes VALUES ('13', 'No answer from user (user alerted)', 'The destination responds to the connection request but fails to complete the connection within the prescribed time. The problem is at the remote end of the connection.');
INSERT INTO isdn_error_codes VALUES ('15', 'Call rejected', 'The destination is capable of accepting the call but rejected the call for an unknown reason.');
INSERT INTO isdn_error_codes VALUES ('16', 'Number changed', 'The ISDN number used to set up the call is not assigned to any system.');
INSERT INTO isdn_error_codes VALUES ('1A', 'Non-selected user clearing', 'The destination is capable of accepting the call but rejected the call because it was not assigned to the user.');
INSERT INTO isdn_error_codes VALUES ('1B', 'Designation out of order', 'The destination cannot be reached because the interface is not functioning correctly, and a signaling message cannot be delivered. This might be a temporary condition, but it could last for an extended period of time. For example, the remote equipment might be turned off.');
INSERT INTO isdn_error_codes VALUES ('1C', 'Invalid number format', 'The connection could be established because the destination address was presented in an unrecognizable format or because the destination address was incomplete.');
INSERT INTO isdn_error_codes VALUES ('1D', 'Facility rejected', 'The facility requested by the user cannot be provided by the network.');
INSERT INTO isdn_error_codes VALUES ('1E', 'Response to STATUS ENQUIRY', 'The status message was generated in direct response to the prior receipt of a status enquiry message.');
INSERT INTO isdn_error_codes VALUES ('1F', 'Normal, unspecified', 'Reports the occurrence of a normal event when no standard cause applies. No action required.');
INSERT INTO isdn_error_codes VALUES ('2', 'No route to specified transit network', 'The ISDN exchange is asked to route the call through an unrecognized intermediate network.');
INSERT INTO isdn_error_codes VALUES ('22', 'No circuit/channel available', 'The connection cannot be established because no appropriate channel is available to take the call.');
INSERT INTO isdn_error_codes VALUES ('26', 'Network out of order', 'The destination cannot be reached because the network is not functioning correctly, and the condition might last for an extended period of time. An immediate reconnect attempt will probably be unsuccessful.');
INSERT INTO isdn_error_codes VALUES ('29', 'Temporary failure', 'An error occurred because the network is not functioning correctly. The problem will be resolved shortly.');
INSERT INTO isdn_error_codes VALUES ('2A', 'Switching equipment congestion', 'The destination cannot be reached because the network switching equipment is temporarily overloaded.');
INSERT INTO isdn_error_codes VALUES ('2B', 'Access information discarded', 'The network cannot provide the requested access information.');
INSERT INTO isdn_error_codes VALUES ('2C', 'Requested circuit/channel not available', 'The remote equipment cannot provide the requested channel for an unknown reason. This might be a temporary problem.');
INSERT INTO isdn_error_codes VALUES ('2F', 'Resources unavailable, unspecified', 'The requested channel or service is unavailable for an unknown reason. This might be a temporary problem.');
INSERT INTO isdn_error_codes VALUES ('3', 'No route to destination', 'The call was routed through an intermediate network that does not serve the destination address.');
INSERT INTO isdn_error_codes VALUES ('31', 'Quality of service unavailable', 'The requested quality of service cannot be provided by the network. This might be a subscription problem.');
INSERT INTO isdn_error_codes VALUES ('32', 'Requested facility not subscribed', 'The remote equipment supports the requested supplementary service by subscription only.');
INSERT INTO isdn_error_codes VALUES ('39', 'Bearer capability not authorized', 'The user requested a bearer capability that the network provides, but the user is not authorized to use it. This might be a subscription problem.');
INSERT INTO isdn_error_codes VALUES ('3A', 'Bearer capability not presently available', 'The network normally provides the requested bearer capability, but it is unavailable at the present time. This might be due to a temporary network problem or to a subscription problem.');
INSERT INTO isdn_error_codes VALUES ('3F', 'Service or option not available, unspecified', 'The network or remote equipment was unable to provide the requested service option for an unspecified reason. This might be a subscription problem.');
INSERT INTO isdn_error_codes VALUES ('41', 'Bearer capability not implemented', 'The network cannot provide the bearer capability requested by the user.');
INSERT INTO isdn_error_codes VALUES ('42', 'Channel type not implemented', 'The network or the destination equipment does not support the requested channel type.');
INSERT INTO isdn_error_codes VALUES ('45', 'Requested facility not implemented', 'The remote equipment does not support the requested supplementary service.');
INSERT INTO isdn_error_codes VALUES ('46', 'Only restricted digital information bearer capability is available', 'The network is unable to provide unrestricted digital information bearer capability.');
INSERT INTO isdn_error_codes VALUES ('4F', 'Service or option not implemented, unspecified', 'The network or remote equipment is unable to provide the requested service option for an unspecified reason. This might be a subscription problem.');
INSERT INTO isdn_error_codes VALUES ('51', 'Invalid call reference value', 'The remote equipment received a call with a call reference that is not currently in use on the user-network interface.');
INSERT INTO isdn_error_codes VALUES ('52', 'Identified channel does not exist', 'The receiving equipment is requested to use a channel that is not activated on the interface for calls.');
INSERT INTO isdn_error_codes VALUES ('53', 'A suspended call exists, but this call identity does not', 'The network received a call resume request. The call resume request contained a Call Identify information element that indicates that the call identity is being used for a suspended call.');
INSERT INTO isdn_error_codes VALUES ('54', 'Call identity in use', 'The network received a call resume request. The call resume request contained a Call Identify information element that indicates that it is in use for a suspended call.');
INSERT INTO isdn_error_codes VALUES ('55', 'No call suspended', 'The network received a call resume request when there was not a suspended call pending. This might be a transient error that will be resolved by successive call retries.');
INSERT INTO isdn_error_codes VALUES ('56', 'Call having the requested call identity has been cleared', 'The network received a call resume request. The call resume request contained a Call Identity information element, which once indicated a suspended call. However, the suspended call was cleared either by timeout or by the remote user.');
INSERT INTO isdn_error_codes VALUES ('58', 'Incompatible destination', 'Indicates that an attempt was made to connect to non-ISDN equipment. For example, to an analog line.');
INSERT INTO isdn_error_codes VALUES ('5B', 'Invalid transit network selection', 'The ISDN exchange was asked to route the call through an unrecognized intermediate network.');
INSERT INTO isdn_error_codes VALUES ('5F', 'Invalid message, unspecified', 'An invalid message was received, and no standard cause applies. This is usually due to a D-channel error. If this error occurs systematically, report it to your ISDN service provider.');
INSERT INTO isdn_error_codes VALUES ('6', 'Channel unacceptable', 'The service quality of the specified channel is insufficient to accept the connection.');
INSERT INTO isdn_error_codes VALUES ('60', 'Mandatory information element is missing', 'The receiving equipment received a message that did not include one of the mandatory information elements. This is usually due to a D-channel error. If this error occurs systematically, report it to your ISDN service provider.');
INSERT INTO isdn_error_codes VALUES ('61', 'Message type non-existent or not implemented', 'The receiving equipment received an unrecognized message, either because the message type was invalid or because the message type was valid but not supported. The cause is due to either a problem with the remote configuration or a problem with the local D channel.');
INSERT INTO isdn_error_codes VALUES ('62', 'Message not compatible with call state or message type non-existent or not implemented', 'The remote equipment received an invalid message, and no standard cause applies. This cause is due to a D-channel error. If this error occurs systematically, report it to your ISDN service provider.');
INSERT INTO isdn_error_codes VALUES ('63', 'Information element non-existent or not implemented', 'The remote equipment received a message that includes information elements, which were not recognized. This is usually due to a D-channel error. If this error occurs systematically, report it to your ISDN service provider.');
INSERT INTO isdn_error_codes VALUES ('64', 'Invalid information element contents', 'The remote equipment received a message that includes invalid information in the information element. This is usually due to a D-channel error.');
INSERT INTO isdn_error_codes VALUES ('65', 'Message not compatible with call state', 'The remote equipment received an unexpected message that does not correspond to the current state of the connection. This is usually due to a D-channel error.');
INSERT INTO isdn_error_codes VALUES ('66', 'Recovery on timer expires', 'An error-handling (recovery) procedure was initiated by a timer expiry. This is usually a temporary problem.');
INSERT INTO isdn_error_codes VALUES ('6F', 'Protocol error, unspecified', 'An unspecified D-channel error when no other standard cause applies.');
INSERT INTO isdn_error_codes VALUES ('7', 'Call awarded and being delivered in an established channel', 'The user is assigned an incoming call that is being connected to an already-established call channel.');
INSERT INTO isdn_error_codes VALUES ('7F', 'Internetworking, unspecified', 'An event occurred, but the network does not provide causes for the action that it takes. The precise problem is unknown.');



/*
 * # createlang -U postgres plpgsql radius
 */
CREATE OR REPLACE FUNCTION VoIPInsertRecord(StopVoIP.UserName%TYPE, StopVoIP.NASIPAddress%TYPE, StopVoIP.AcctSessionTime%TYPE,
StopVoIP.AcctInputOctets%TYPE, StopVoIP.AcctOutputOctets%TYPE, StopVoIP.CalledStationId%TYPE, StopVoIP.CallingStationId%TYPE,
StopVoIP.AcctDelayTime%TYPE, StopVoIP.h323CallOrigin%TYPE, StopVoIP.h323SetupTime%TYPE, StopVoIP.h323ConnectTime%TYPE, StopVoIP.h323DisconnectTime%TYPE,
StopVoIP.h323DisconnectCause%TYPE, StopVoIP.H323RemoteAddress%TYPE, StopVoIP.H323VoiceQuality%TYPE, StopVoIP.h323ConfID%TYPE) RETURNS BOOLEAN AS '
DECLARE
    key1 ALIAS FOR $10;
    key2 ALIAS FOR $2;
    key3 ALIAS FOR $16;
BEGIN
        PERFORM radacctid FROM StopVoIP WHERE h323SetupTime = $10 AND NASIPAddress = $2 AND h323confid = $16;
        IF NOT FOUND THEN
		INSERT into StopVoIP (
                UserName, NASIPAddress, AcctSessionTime, AcctInputOctets, AcctOutputOctets, CalledStationId, CallingStationId,
                AcctDelayTime, h323callorigin, h323setuptime, h323connecttime, h323disconnecttime, h323disconnectcause,
		H323RemoteAddress, h323voicequality, h323confid) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16);
	RETURN true;
        END IF;
        RETURN false;
END;
' LANGUAGE 'plpgsql';

CREATE OR REPLACE FUNCTION TelephonyInsertRecord(StopTelephony.UserName%TYPE, StopTelephony.NASIPAddress%TYPE, StopTelephony.AcctSessionTime%TYPE,
    StopTelephony.AcctInputOctets%TYPE, StopTelephony.AcctOutputOctets%TYPE, StopTelephony.CalledStationId%TYPE, StopTelephony.CallingStationId%TYPE,
    StopTelephony.AcctDelayTime%TYPE, StopTelephony.CiscoNASPort%TYPE, StopTelephony.h323CallOrigin%TYPE, StopTelephony.h323SetupTime%TYPE,
    StopTelephony.h323ConnectTime%TYPE, StopTelephony.h323DisconnectTime%TYPE, StopTelephony.h323DisconnectCause%TYPE, 
    StopTelephony.H323VoiceQuality%TYPE, StopTelephony.h323ConfID%TYPE) RETURNS BOOLEAN AS '
DECLARE
BEGIN
        PERFORM radacctid FROM StopTelephony WHERE h323SetupTime = $11 AND NASIPAddress = $2 AND h323confid = $16;
        IF NOT FOUND THEN
	 	INSERT into StopTelephony (
                UserName, NASIPAddress, AcctSessionTime, AcctInputOctets, AcctOutputOctets, CalledStationId, CallingStationId,
                AcctDelayTime, CiscoNASPort, h323callorigin, h323setuptime, h323connecttime, h323disconnecttime, h323disconnectcause,
		h323voicequality, h323confid) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16);
	RETURN true;
        END IF;
        RETURN false;
END;
' LANGUAGE 'plpgsql';
