-----------------------------------------------------------------------------
-- $Id$                 ␉····   --
--                                                                         --
--  schema.sql                       rlm_sql - FreeRADIUS SQLite Module    --
--                                                                         --
--     Database schema for SQLite rlm_sql module for DHCP                  --
--                                                                         --
-----------------------------------------------------------------------------

--
-- Table structure for table 'dhcpgroupreply'
--
CREATE TABLE IF NOT EXISTS dhcpgroupreply (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	groupname varchar(64) NOT NULL default '',
	attribute varchar(64) NOT NULL default '',
	op char(2) NOT NULL DEFAULT '=',
	value varchar(253) NOT NULL default '',
	context varchar(16) NOT NULL default ''
);
CREATE INDEX dhcpgroupreply_groupname ON dhcpgroupreply(context,groupname);

--
-- Table structure for table 'dhcpreply'
--
CREATE TABLE IF NOT EXISTS dhcpreply (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	identifier varchar(253) NOT NULL default '',
	attribute varchar(64) NOT NULL default '',
	op char(2) NOT NULL DEFAULT '=',
	value varchar(253) NOT NULL default '',
	context varchar(16) NOT NULL default ''
);
CREATE INDEX dhcpreply_identifier ON dhcpreply(context,identifier);

--
-- Table structure for table 'dhcpgroup'
--
CREATE TABLE IF NOT EXISTS dhcpgroup (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	identifier varchar(253) NOT NULL default '',
	groupname varchar(64) NOT NULL default '',
	priority int(11) NOT NULL default '1',
	context varchar(16) NOT NULL default ''
);
CREATE INDEX dhcpgroup_identifier ON dhcpgroup(context,identifier);
