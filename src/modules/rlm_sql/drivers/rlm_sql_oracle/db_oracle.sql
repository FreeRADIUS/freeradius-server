/*
 * $Id$
 *
 * Oracle schema for FreeRADIUS
 *
 *
 * NOTE: Which columns are NULLable??
 */

/*
 * Table structure for table 'dictionary'
 */
CREATE TABLE dictionary (
	id		INT PRIMARY KEY,
	type		VARCHAR(30),
	attribute	VARCHAR(32),
	value		VARCHAR(32),
	format		VARCHAR(20),
	vendor		VARCHAR(32)
);
CREATE SEQUENCE dictionary_seq START WITH 1 INCREMENT BY 1;

/*
 * Table structure for table 'nas'
 */
CREATE TABLE nas (
	id 		INT PRIMARY KEY,
	nasname		VARCHAR(128),
	shortname	VARCHAR(32),
	ipaddr		VARCHAR(15),
	type		VARCHAR(30),
	ports		INT,
	secret		VARCHAR(60),
	community	VARCHAR(50),
	snmp		VARCHAR(10)
);
CREATE SEQUENCE nas_seq START WITH 1 INCREMENT BY 1;

/*
 * Table structure for table 'radacct'
 */
CREATE TABLE radacct (
	radacctid		INT PRIMARY KEY,
	acctsessionid		VARCHAR(32) NOT NULL,
	acctuniqueid		VARCHAR(32),
	username		VARCHAR(32) NOT NULL,
	realm			VARCHAR(30),
	nasipaddress		VARCHAR(15) NOT NULL,
	nasportid		NUMERIC(12),
	nasporttype		VARCHAR(32),
	acctstarttime		DATE,
	acctstoptime		DATE,
	acctsessiontime		NUMERIC(12),
	acctauthentic		VARCHAR(32),
	connectinfo_start	VARCHAR(32),
	connectinfo_stop	VARCHAR(32),
	acctinputoctets		NUMERIC(12),
	acctoutputoctets	NUMERIC(12),
	calledstationid		VARCHAR(10),
	callingstationid	VARCHAR(10),
	acctterminatecause	VARCHAR(32),
	servicetype		VARCHAR(32),
	framedprotocol		VARCHAR(32),
	framedipaddress		VARCHAR(15),
	acctstartdelay		NUMERIC(12),
	acctstopdelay		NUMERIC(12)
);
CREATE UNIQUE INDEX radacct_idx1
       ON radacct(acctsessionid,username,acctstarttime,
		acctstoptime,nasipaddress,framedipaddress);

CREATE SEQUENCE radacct_seq START WITH 1 INCREMENT BY 1;

/* Trigger to emulate a serial # on the primary key */
CREATE OR REPLACE TRIGGER radacct_serialnumber 
	BEFORE INSERT OR UPDATE OF radacctid ON radacct
	FOR EACH ROW
	BEGIN
		if ( :new.radacctid = 0 or :new.radacctid is null ) then
			SELECT radacct_seq.nextval into :new.radacctid from dual;
		end if;
	END;
/

/*
 * Table structure for table 'radcheck'
 */
CREATE TABLE radcheck (
	id 		INT PRIMARY KEY,
	username	VARCHAR(30) NOT NULL,
	attribute	VARCHAR(30),
	value		VARCHAR(40)
);
CREATE SEQUENCE radcheck_seq START WITH 1 INCREMENT BY 1;

/* Trigger to emulate a serial # on the primary key */
CREATE OR REPLACE TRIGGER radcheck_serialnumber 
	BEFORE INSERT OR UPDATE OF id ON radcheck
	FOR EACH ROW
	BEGIN
		if ( :new.id = 0 or :new.id is null ) then
			SELECT radcheck_seq.nextval into :new.id from dual;
		end if;
	END;
/

/*
 * Table structure for table 'radgroupcheck'
 */
CREATE TABLE radgroupcheck (
	id 		INT PRIMARY KEY,
	groupname	VARCHAR(20) UNIQUE NOT NULL,
	attribute	VARCHAR(40),
	value		VARCHAR(40)
);
CREATE SEQUENCE radgroupcheck_seq START WITH 1 INCREMENT BY 1;

/*
 * Table structure for table 'radgroupreply'
 */
CREATE TABLE radgroupreply (
	id		INT PRIMARY KEY,
	GroupName	VARCHAR(20) UNIQUE NOT NULL,
	Attribute	VARCHAR(40),
	Value		VARCHAR(40)
);
CREATE SEQUENCE radgroupreply_seq START WITH 1 INCREMENT BY 1;

/*
 * Table structure for table 'radreply'
 */
CREATE TABLE radreply (
	id		INT PRIMARY KEY,
	UserName	VARCHAR(30) NOT NULL,
	Attribute	VARCHAR(30),
	Value		VARCHAR(40)
);
CREATE INDEX radreply_idx1 ON radreply(UserName);
CREATE SEQUENCE radreply_seq START WITH 1 INCREMENT BY 1;

/* Trigger to emulate a serial # on the primary key */
CREATE OR REPLACE TRIGGER radreply_serialnumber 
	BEFORE INSERT OR UPDATE OF id ON radreply
	FOR EACH ROW
	BEGIN
		if ( :new.id = 0 or :new.id is null ) then
			SELECT radreply_seq.nextval into :new.id from dual;
		end if;
	END;
/

/*
 * Table structure for table 'usergroup'
 */
CREATE TABLE usergroup (
	id		INT PRIMARY KEY,
	UserName	VARCHAR(30) UNIQUE NOT NULL,
	GroupName	VARCHAR(30)
);
CREATE SEQUENCE usergroup_seq START WITH 1 INCREMENT BY 1;

/*
 * Table structure for table 'realmgroup'
 */
CREATE TABLE realmgroup (
	id 		INT PRIMARY KEY,
	RealmName	VARCHAR(30) UNIQUE NOT NULL,
	GroupName	VARCHAR(30)
);
CREATE SEQUENCE realmgroup_seq START WITH 1 INCREMENT BY 1;

CREATE TABLE realms (
	id		INT PRIMARY KEY,
	realmname	VARCHAR(64),
	nas		VARCHAR(128),
	authport	INT,
	options		VARCHAR(128)
);
CREATE SEQUENCE realms_seq START WITH 1 INCREMENT BY 1;
