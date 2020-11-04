/*
 * $Id$
 *
 * Oracle schema for DHCP for FreeRADIUS
 *
 */

/*
 * Table structure for table 'dhcpgroupreply'
 */
CREATE TABLE dhcpgroupreply (
	id		INT PRIMARY KEY,
	groupname	VARCHAR(64) NOT NULL,
	attribute	VARCHAR(64) NOT NULL,
	op		CHAR(2) NOT NULL,
	value		VARCHAR(253) NOT NULL,
	context		VARCHAR(16) NOT NULL
);
CREATE INDEX dhcpgroupreply_idx1 ON dhcpgroupreply(context,groupname);
CREATE SEQUENCE dhcpgroupreply_seq START WITH 1 INCREMENT BY 1;

/* Trigger to emulate a serial # on the primary key */
CREATE OR REPLACE TRIGGER dhcpgroupreply_serialnumber
	BEFORE INSERT OR UPDATE OF id ON dhcpgroupreply
	FOR EACH ROW
	BEGIN
		if ( :new.id = 0 or :new.id is null ) then
			SELECT dhcpgroupreply_seq.nextval into :new.id from dual;
		end if;
	END;
/

/*
 * Table structure for table 'dhcpreply'
 */
CREATE TABLE dhcpreply (
	id		INT PRIMARY KEY,
	identifier	VARCHAR(253) NOT NULL,
	attribute	VARCHAR(64) NOT NULL,
	op		CHAR(2) NOT NULL,
	value		VARCHAR(253) NOT NULL,
	context		VARCHAR(16) NOT NULL
);
CREATE INDEX dhcpreply_idx1 ON dhcpreply(context,identifier);
CREATE SEQUENCE dhcpreply_seq START WITH 1 INCREMENT BY 1;

/* Trigger to emulate a serial # on the primary key */
CREATE OR REPLACE TRIGGER dhcpreply_serialnumber
	BEFORE INSERT OR UPDATE OF id ON dhcpreply
	FOR EACH ROW
	BEGIN
		if ( :new.id = 0 or :new.id is null ) then
			SELECT dhcpreply_seq.nextval into :new.id from dual;
		end if;
	END;
/

/*
 * Table structure for table 'dhcpgroup'
 */
CREATE TABLE dhcpgroup (
	id		INT PRIMARY KEY,
	identifier	VARCHAR(253) NOT NULL,
	groupname	VARCHAR(64) NOT NULL,
	priority	INT NOT NULL,
	context		VARCHAR(16) NOT NULL
);
CREATE INDEX dhcpgroup_idx1 ON dhcpgroup(context,identifier);
CREATE SEQUENCE dhcpgroup_seq START WITH 1 INCREMENT BY 1;

/* Trigger to emulate a serial # on the primary key */
CREATE OR REPLACE TRIGGER dhcpgroup_serialnumber
	BEFORE INSERT OR UPDATE OF id ON dhcpgroup
	FOR EACH ROW
	BEGIN
		if ( :new.id = 0 or :new.id is null ) then
			SELECT dhcpgroup_seq.nextval into :new.id from dual;
		end if;
	END;
/

