#
# $Id$
#
# PostgreSQL schema for DHCP for FreeRADIUS
#
#

#
# Table structure for table 'dhcpgroupreply'
#
CREATE TABLE IF NOT EXISTS dhcpgroupreply (
  id int(11) unsigned NOT NULL auto_increment,
  groupname varchar(64) NOT NULL default '',
  attribute varchar(64) NOT NULL default '',
  op char(2) NOT NULL DEFAULT '=',
  value varchar(253) NOT NULL default '',
  context varchar(16) NOT NULL default '',
  PRIMARY KEY (id),
  KEY groupname (context,groupname(32))
);

#
# Table structure for table 'dhcpreply'
#
CREATE TABLE IF NOT EXISTS dhcpreply (
  id int(11) unsigned NOT NULL auto_increment,
  identifier varchar(253) NOT NULL default '',
  attribute varchar(64) NOT NULL default '',
  op char(2) NOT NULL DEFAULT '=',
  value varchar(253) NOT NULL default '',
  context varchar(16) NOT NULL default '',
  PRIMARY KEY (id),
  KEY identifier (context,identifier(32))
);

#
# Table structure for table 'dhcpgroup'
#
CREATE TABLE IF NOT EXISTS dhcpgroup (
  id int(11) unsigned NOT NULL auto_increment,
  identifier varchar(253) NOT NULL default '',
  groupname varchar(64) NOT NULL default '',
  priority int(11) NOT NULL default '1',
  context varchar(16) NOT NULL default '',
  PRIMARY KEY (id),
  KEY identifier (context,identifier(32))
);
