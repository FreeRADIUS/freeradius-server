/*
 * $Id$
 *
 */


/*
 * Table structure for table 'totacct'
 */
CREATE TABLE totacct (
        totacctid	INT PRIMARY KEY,
        username        varchar(64) DEFAULT '' NOT NULL,
        acctdate        DATE DEFAULT sysdate NOT NULL,
        connnum         NUMERIC(12),
        conntotduration NUMERIC(12),
        connmaxduration NUMERIC(12),
        connminduration NUMERIC(12),
        inputoctets     NUMERIC(12),
        outputoctets    NUMERIC(12),
        nasipaddress    varchar(15) default NULL
);
CREATE INDEX totacct_acctdate_idx ON totacct (acctdate);
CREATE INDEX totacct_nasipaddress_idx ON totacct (nasipaddress);
CREATE INDEX totacct_nasondate_idx ON totacct (acctdate, nasipaddress);
CREATE INDEX totacct_username_idx ON totacct (username);
CREATE INDEX totacct_userondate_idx ON totacct (username, acctdate);

CREATE SEQUENCE totacct_seq START WITH 1 INCREMENT BY 1;

/* Trigger to emulate a serial # on the primary key */
CREATE OR REPLACE TRIGGER totacct_serialnumber
        BEFORE INSERT OR UPDATE OF totacctid ON totacct
        FOR EACH ROW
        BEGIN
                if ( :new.totacctid = 0 or :new.totacctid is null ) then
                        SELECT totacct_seq.nextval into :new.totacctid from dual;
                end if;
        END;
/

