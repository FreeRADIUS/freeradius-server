-- $Id$

-- create plpgsql language
CREATE FUNCTION "plpgsql_call_handler" () RETURNS LANGUAGE_HANDLER AS '$libdir/plpgsql' LANGUAGE C;
CREATE TRUSTED LANGUAGE "plpgsql" HANDLER "plpgsql_call_handler";


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

-- Some sample database VIEWs to simplify billing queries.

CREATE OR REPLACE VIEW StartVoIPd AS
SELECT DISTINCT ON(h323SetupTime, CallID) * FROM StartVoIP;

CREATE OR REPLACE VIEW StopVoIPd AS
SELECT DISTINCT ON(h323SetupTime, CallID) * FROM StopVoIP;


CREATE OR REPLACE VIEW call_history_csps2 AS
SELECT StartVoIP.h323ConnectTime, StopVoIP.h323DisconnectTime, (EXTRACT(EPOCH FROM(StopVoIP.h323DisconnectTime - StartVoIP.h323ConnectTime)))::BIGINT AS CallLength, StopVoIP.CalledStationId AS Number, StopVoIP.UserName AS UserName, StopVoIP.CallingStationId AS CallerID, StopVoIP.CallID
FROM StopVoIPd AS StopVoIP LEFT OUTER JOIN StartVoIPd AS StartVoIP
ON (StopVoIP.CallID = StartVoIP.CallID)
WHERE StopVoIP.NASIPAddress = '212.50.54.122'
ORDER BY StartVoIP.h323ConnectTime;

CREATE OR REPLACE VIEW call_history_csps AS
SELECT CAST ((h323DisconnectTime::date AT TIME ZONE 'UTC') AS date) AS Date, CAST ((h323DisconnectTime AT TIME ZONE 'UTC') AS time without time zone) AS Time, AcctSessionTime AS Length, CalledStationId AS Number, UserName AS UserName, CallingStationId AS CallerID, CallID
FROM StopVoIP
WHERE NASIPAddress = '212.50.54.122';

CREATE OR REPLACE VIEW call_history AS
SELECT CAST ((h323SetupTime::date AT TIME ZONE 'UTC') AS date) AS Date, CAST ((h323SetupTime AT TIME ZONE 'UTC') AS time without time zone) AS Time, AcctSessionTime AS Length, CalledStationId AS Number, UserName AS UserName, CallingStationId AS CallerID, H323RemoteAddress, NASIPAddress, CallID
FROM StopVoIP;

CREATE OR REPLACE VIEW call_history AS
SELECT CAST ((pots.h323SetupTime::date AT TIME ZONE 'UTC') AS date) AS Date, CAST ((pots.h323SetupTime AT TIME ZONE 'UTC') AS time without time zone) AS Time, pots.AcctSessionTime AS Length, pots.CalledStationId AS Number, ip.H323RemoteAddress AS cust_ip, ip.NASIPAddress AS gw_ip
FROM StopTelephony AS pots LEFT OUTER JOIN StopVoIP AS ip
ON (pots.CallID = ip.CallID);

CREATE OR REPLACE VIEW call_history_customer AS
SELECT Date, Time, Length, Number, cust_ip, gw_ip, CustomerIP.Company AS Company
FROM call_history LEFT OUTER JOIN customerip
ON (call_history.cust_ip = CustomerIP.IpAddr);

CREATE OR REPLACE VIEW customerip AS
SELECT gw.cust_gw AS IpAddr, cust.company AS Company, cust.customer AS Customer, gw.location AS Location
FROM customers  AS cust, cust_gw AS gw
WHERE cust.cust_id = gw.cust_id;

CREATE OR REPLACE VIEW VoIP AS
SELECT RadAcctId AS ID, NASIPAddress AS GWIP, AcctSessionTime AS Call_Seconds, chop_number_country(CalledStationId) AS Country, chop_number_city(CalledStationId) AS City,chop_number_number(CalledStationId) AS Number, chop_number(CalledStationId) AS Original_Number, EXTRACT(YEAR FROM (h323setuptime AT TIME ZONE 'UTC')) AS Year, EXTRACT(MONTH FROM (h323setuptime AT TIME ZONE 'UTC')) AS Month, EXTRACT(DAY FROM (h323setuptime AT TIME ZONE 'UTC')) AS Day, CAST ((h323SetupTime AT TIME ZONE 'UTC') AS time without time zone) AS Time, h323DisconnectCause AS error_code, H323RemoteAddress AS Remote_IP, CallID
FROM StopVoIP;

CREATE OR REPLACE VIEW Telephony AS
SELECT RadAcctId AS ID, NASIPAddress AS GWIP, AcctSessionTime AS Call_Seconds, chop_number_country(CalledStationId) AS Country, chop_number_city(CalledStationId) AS City,chop_number_number(CalledStationId) AS Number, chop_number(CalledStationId) AS Original_Number, EXTRACT(YEAR FROM (h323setuptime AT TIME ZONE 'UTC')) AS Year, EXTRACT(MONTH FROM (h323setuptime AT TIME ZONE 'UTC')) AS Month, EXTRACT(DAY FROM (h323setuptime AT TIME ZONE 'UTC')) AS Day, CAST ((h323SetupTime AT TIME ZONE 'UTC') AS time without time zone) AS Time, h323DisconnectCause AS error_code, split_part(split_part(CiscoNASPort,':',1),' ',2) AS PRI, split_part(CiscoNASPort,':',3) AS PRI_channel, CiscoNASPort AS isdn_port, CallID AS ConfID
FROM StopTelephony;

CREATE OR REPLACE VIEW calls AS
SELECT Date, Time, Length, Number, cust_ip, gw_ip
FROM call_history
WHERE Length > 0
ORDER BY Date, Time, Number, Length, cust_ip ASC;

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



CREATE OR REPLACE FUNCTION VoIPInsertRecord(StopVoIP.UserName%TYPE, StopVoIP.NASIPAddress%TYPE, StopVoIP.AcctSessionTime%TYPE,
StopVoIP.AcctInputOctets%TYPE, StopVoIP.AcctOutputOctets%TYPE, StopVoIP.CalledStationId%TYPE, StopVoIP.CallingStationId%TYPE,
StopVoIP.AcctDelayTime%TYPE, StopVoIP.h323CallOrigin%TYPE, StopVoIP.h323SetupTime%TYPE, StopVoIP.h323ConnectTime%TYPE, StopVoIP.h323DisconnectTime%TYPE,
StopVoIP.h323DisconnectCause%TYPE, StopVoIP.H323RemoteAddress%TYPE, StopVoIP.H323VoiceQuality%TYPE, StopVoIP.h323ConfID%TYPE) RETURNS BOOLEAN AS '
DECLARE
    key1 ALIAS FOR $10;
    key2 ALIAS FOR $2;
    key3 ALIAS FOR $16;
BEGIN
        PERFORM radacctid FROM StopVoIP WHERE h323SetupTime = $10 AND NASIPAddress = $2 AND CallID = $16;
        IF NOT FOUND THEN
		INSERT into StopVoIP (
                UserName, NASIPAddress, AcctSessionTime, AcctInputOctets, AcctOutputOctets, CalledStationId, CallingStationId,
                AcctDelayTime, h323callorigin, h323setuptime, h323connecttime, h323disconnecttime, h323disconnectcause,
		H323RemoteAddress, h323voicequality, CallID) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16);
	RETURN true;
        END IF;
        RETURN false;
END;
' LANGUAGE 'plpgsql';

CREATE OR REPLACE FUNCTION TelephonyInsertRecord(StopTelephony.UserName%TYPE, StopTelephony.NASIPAddress%TYPE, StopTelephony.AcctSessionTime%TYPE,
    StopTelephony.AcctInputOctets%TYPE, StopTelephony.AcctOutputOctets%TYPE, StopTelephony.CalledStationId%TYPE, StopTelephony.CallingStationId%TYPE,
    StopTelephony.AcctDelayTime%TYPE, StopTelephony.CiscoNASPort%TYPE, StopTelephony.h323CallOrigin%TYPE, StopTelephony.h323SetupTime%TYPE,
    StopTelephony.h323ConnectTime%TYPE, StopTelephony.h323DisconnectTime%TYPE, StopTelephony.h323DisconnectCause%TYPE,
    StopTelephony.H323VoiceQuality%TYPE, StopTelephony.CallID%TYPE) RETURNS BOOLEAN AS '
DECLARE
BEGIN
        PERFORM radacctid FROM StopTelephony WHERE h323SetupTime = $11 AND NASIPAddress = $2 AND CallID = $16;
        IF NOT FOUND THEN
	 	INSERT into StopTelephony (
                UserName, NASIPAddress, AcctSessionTime, AcctInputOctets, AcctOutputOctets, CalledStationId, CallingStationId,
                AcctDelayTime, CiscoNASPort, h323callorigin, h323setuptime, h323connecttime, h323disconnecttime, h323disconnectcause,
		h323voicequality, CallID) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16);
	RETURN true;
        END IF;
        RETURN false;
END;
' LANGUAGE 'plpgsql';
