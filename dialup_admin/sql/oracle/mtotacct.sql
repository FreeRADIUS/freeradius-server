/*
 * $Id$
 *
 */


/*
 * Table structure for table 'mtotacct'
 */
CREATE TABLE mtotacct (
	mtotacctid	INT PRIMARY KEY,
	username	varchar(64) DEFAULT '' NOT NULL,
	acctdate	DATE DEFAULT sysdate NOT NULL,
	connnum		NUMERIC(12),
	conntotduration	NUMERIC(12),
	connmaxduration	NUMERIC(12),
	connminduration	NUMERIC(12),
	inputoctets	NUMERIC(12),
	outputoctets	NUMERIC(12),
	nasipaddress	varchar(15) default NULL
);

CREATE INDEX mtotacct_acctdate_idx ON mtotacct (acctdate);
CREATE INDEX mtotacct_nasipaddress_idx ON mtotacct (nasipaddress);
CREATE INDEX mtotacct_username_idx ON mtotacct (username);
CREATE INDEX mtotacct_userondate_idx ON mtotacct (username, acctdate);

CREATE SEQUENCE mtotacct_seq START WITH 1 INCREMENT BY 1;

/* Trigger to emulate a serial # on the primary key */
CREATE OR REPLACE TRIGGER mtotacct_serialnumber
        BEFORE INSERT OR UPDATE OF mtotacctid ON mtotacct
        FOR EACH ROW
        BEGIN
                if ( :new.mtotacctid = 0 or :new.mtotacctid is null ) then
                        SELECT mtotacct_seq.nextval into :new.mtotacctid from dual;
                end if;
        END;
/

