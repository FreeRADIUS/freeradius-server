/*
 * $Id$
 *
 * PostgreSQL schema for DHCP for FreeRADIUS
 *
 */

/*
 * Table structure for table 'dhcpgroupreply'
 */
CREATE TABLE IF NOT EXISTS dhcpgroupreply (
	id			serial PRIMARY KEY,
	GroupName		text NOT NULL DEFAULT '',
	Attribute		text NOT NULL DEFAULT '',
	op			VARCHAR(2) NOT NULL DEFAULT '=',
	Value			text NOT NULL DEFAULT '',
	Context			text NOT NULL DEFAULT ''
);
CREATE INDEX dhcpgroupreply_GroupName ON dhcpgroupreply (Context,GroupName,Attribute);

/*
 * Table structure for table 'dhcpreply'
 */
CREATE TABLE IF NOT EXISTS dhcpreply (
	id			serial PRIMARY KEY,
	Identifier		text NOT NULL DEFAULT '',
	Attribute		text NOT NULL DEFAULT '',
	op			VARCHAR(2) NOT NULL DEFAULT '=',
	Value			text NOT NULL DEFAULT '',
	Context			text NOT NULL DEFAULT ''
);
CREATE INDEX dhcpreply_Identifier ON dhcpreply (Context,Identifier,Attribute);

/*
 * Table structure for table 'dhcpgroup'
 */
CREATE TABLE IF NOT EXISTS dhcpgroup (
	id			serial PRIMARY KEY,
	Identifier		text NOT NULL DEFAULT '',
	GroupName		text NOT NULL DEFAULT '',
	Priority		integer NOT NULL DEFAULT 0,
	Context			text NOT NULL DEFAULT ''
);
CREATE INDEX dhcpgroup_Identifier ON dhcpgroup (Context,Identifier);
