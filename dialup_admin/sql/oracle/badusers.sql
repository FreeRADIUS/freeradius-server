/*
 * $Id$
 *
 */

/*
 * Table structure for table 'radcheck'
 */

CREATE TABLE badusers (
	id		INT PRIMARY KEY,
	username	VARCHAR(30) DEFAULT '' NOT NULL,
	incidentdate	TIMESTAMP WITH TIME ZONE DEFAULT sysdate NOT NULL,
	reason		VARCHAR(128) DEFAULT '' NOT NULL,
	admin		VARCHAR(128) DEFAULT '-' NOT NULL
);
CREATE SEQUENCE badusers_seq START WITH 1 INCREMENT BY 1;
CREATE INDEX badusers_incidentdate_idx ON badusers (incidentdate);
CREATE INDEX badusers_username_idx ON badusers (username);

/* Trigger to emulate a serial # on the primary key */
CREATE OR REPLACE TRIGGER badusers_serialnumber
        BEFORE INSERT OR UPDATE OF id ON badusers
        FOR EACH ROW
        BEGIN
                if ( :new.id = 0 or :new.id is null ) then
                        SELECT badusers_seq.nextval into :new.id from dual;
                end if;
        END;
/

