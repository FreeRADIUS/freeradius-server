/*
 * $Id$
 *
 */

/*
 * Table structure for table 'userinfo'
 */

CREATE TABLE userinfo (
	id		INT PRIMARY KEY,
	username	VARCHAR(128) DEFAULT '' NOT NULL,
	name		VARCHAR(128) DEFAULT '' NOT NULL,
	mail		VARCHAR(128) DEFAULT '' NOT NULL,
	department	VARCHAR(128) DEFAULT '' NOT NULL,
	workphone	VARCHAR(128) DEFAULT '' NOT NULL,
	homephone	VARCHAR(128) DEFAULT '' NOT NULL,
	mobile		VARCHAR(128) DEFAULT '' NOT NULL 
);
CREATE INDEX userinfo_department_idx ON userinfo (department);
CREATE INDEX userinfo_username_idx ON userinfo (username);
CREATE SEQUENCE userinfo_seq START WITH 1 INCREMENT BY 1;


/* Trigger to emulate a serial # on the primary key */
CREATE OR REPLACE TRIGGER userinfo_serialnumber
        BEFORE INSERT OR UPDATE OF id ON userinfo
        FOR EACH ROW
        BEGIN
                if ( :new.id = 0 or :new.id is null ) then
                        SELECT userinfo_seq.nextval into :new.id from dual;
                end if;
        END;
/
