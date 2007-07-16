###########################################################################
#  db_mysql.sql                     rlm_sql - FreeRADIUS SQL Module       #
#                                                                         #
#     Database schema for MySQL rlm_sql module                            #
#                                                                         #
#     To load:                                                            #
#         mysql -uroot -prootpass radius < db_mysql.sql                   #
#                                                                         #
#                                   Mike Machado <mike@innercite.com>     #
###########################################################################
#
# Table structure for table 'radacct'
#

CREATE TABLE radacct (
  RadAcctId bigint(21) NOT NULL auto_increment,
  AcctSessionId varchar(32) NOT NULL default '',
  AcctUniqueId varchar(32) NOT NULL default '',
  UserName varchar(64) NOT NULL default '',
  Realm varchar(64) default '',
  NASIPAddress varchar(15) NOT NULL default '',
  NASPortId varchar(15) default NULL,
  NASPortType varchar(32) default NULL,
  AcctStartTime datetime NOT NULL default '0000-00-00 00:00:00',
  AcctStopTime datetime NOT NULL default '0000-00-00 00:00:00',
  AcctSessionTime int(12) default NULL,
  AcctAuthentic varchar(32) default NULL,
  ConnectInfo_start varchar(50) default NULL,
  ConnectInfo_stop varchar(50) default NULL,
  AcctInputOctets bigint(20) default NULL,
  AcctOutputOctets bigint(20) default NULL,
  CalledStationId varchar(50) NOT NULL default '',
  CallingStationId varchar(50) NOT NULL default '',
  AcctTerminateCause varchar(32) NOT NULL default '',
  ServiceType varchar(32) default NULL,
  FramedProtocol varchar(32) default NULL,
  FramedIPAddress varchar(15) NOT NULL default '',
  AcctStartDelay int(12) default NULL,
  AcctStopDelay int(12) default NULL,
  XAscendSessionSvrKey varchar(10) default NULL,
  PRIMARY KEY  (RadAcctId),
  KEY UserName (UserName),
  KEY FramedIPAddress (FramedIPAddress),
  KEY AcctSessionId (AcctSessionId),
  KEY AcctUniqueId (AcctUniqueId),
  KEY AcctStartTime (AcctStartTime),
  KEY AcctStopTime (AcctStopTime),
  KEY NASIPAddress (NASIPAddress)
) ;

#
# Table structure for table 'radcheck'
#

CREATE TABLE radcheck (
  id int(11) unsigned NOT NULL auto_increment,
  UserName varchar(64) NOT NULL default '',
  Attribute varchar(32)  NOT NULL default '',
  op char(2) NOT NULL DEFAULT '==',
  Value varchar(253) NOT NULL default '',
  PRIMARY KEY  (id),
  KEY UserName (UserName(32))
) ;

#
# Table structure for table 'radgroupcheck'
#

CREATE TABLE radgroupcheck (
  id int(11) unsigned NOT NULL auto_increment,
  GroupName varchar(64) NOT NULL default '',
  Attribute varchar(32)  NOT NULL default '',
  op char(2) NOT NULL DEFAULT '==',
  Value varchar(253)  NOT NULL default '',
  PRIMARY KEY  (id),
  KEY GroupName (GroupName(32))
) ;

#
# Table structure for table 'radgroupreply'
#

CREATE TABLE radgroupreply (
  id int(11) unsigned NOT NULL auto_increment,
  GroupName varchar(64) NOT NULL default '',
  Attribute varchar(32)  NOT NULL default '',
  op char(2) NOT NULL DEFAULT '=',
  Value varchar(253)  NOT NULL default '',
  PRIMARY KEY  (id),
  KEY GroupName (GroupName(32))
) ;

#
# Table structure for table 'radreply'
#

CREATE TABLE radreply (
  id int(11) unsigned NOT NULL auto_increment,
  UserName varchar(64) NOT NULL default '',
  Attribute varchar(32) NOT NULL default '',
  op char(2) NOT NULL DEFAULT '=',
  Value varchar(253) NOT NULL default '',
  PRIMARY KEY  (id),
  KEY UserName (UserName(32))
) ;


#
# Table structure for table 'usergroup'
#

CREATE TABLE usergroup (
  UserName varchar(64) NOT NULL default '',
  GroupName varchar(64) NOT NULL default '',
  priority int(11) NOT NULL default '1',
  KEY UserName (UserName(32))
) ;

#
# Table structure for table 'radpostauth'
#

CREATE TABLE radpostauth (
  id int(11) NOT NULL auto_increment,
  user varchar(64) NOT NULL default '',
  pass varchar(64) NOT NULL default '',
  reply varchar(32) NOT NULL default '',
  date timestamp(14) NOT NULL,
  PRIMARY KEY  (id)
) ;

######################################################################
#
#  The next table is commented out because it is not
#  currently used in the server.
#

#
# Table structure for table 'dictionary'
#
#CREATE TABLE dictionary (
#  id int(10) DEFAULT '0' NOT NULL auto_increment,
#  Type varchar(30),
#  Attribute varchar(64),
#  Value varchar(64),
#  Format varchar(20),
#  Vendor varchar(32),
#  PRIMARY KEY (id)
#);

#
# Table structure for table 'nas'
#
CREATE TABLE nas (
  id int(10) NOT NULL auto_increment,
  nasname varchar(128) NOT NULL,
  shortname varchar(32),
  type varchar(30) DEFAULT 'other',
  ports int(5),
  secret varchar(60) DEFAULT 'secret' NOT NULL,
  community varchar(50),
  description varchar(200) DEFAULT 'RADIUS Client',
  PRIMARY KEY (id),
  KEY nasname (nasname)
);

#
# Table structure for table 'radippool'
#
CREATE TABLE radippool (
  id                    int(11) unsigned NOT NULL auto_increment,
  pool_name             varchar(30) NOT NULL,
  FramedIPAddress       varchar(15) NOT NULL default '',
  NASIPAddress          varchar(15) NOT NULL default '',
  CalledStationId       VARCHAR(30) NOT NULL,
  CallingStationID      VARCHAR(30) NOT NULL,
  expiry_time           DATETIME NOT NULL default '0000-00-00 00:00:00',
  username              varchar(64) NOT NULL default '',
  pool_key              varchar(30) NOT NULL,
  PRIMARY KEY (id)
);
