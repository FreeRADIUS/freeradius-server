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
# MySQL dump 4.0
#
# Host: localhost    Database: radius
#--------------------------------------------------------

#
# Table structure for table 'dictionary'
#
CREATE TABLE dictionary (
  id int(10) DEFAULT '0' NOT NULL auto_increment,
  Type varchar(30),
  Attribute varchar(32),
  Value varchar(32),
  Format varchar(20),
  Vendor varchar(32),
  PRIMARY KEY (id)
);

#
# Table structure for table 'nas'
#
CREATE TABLE nas (
  id int(10) DEFAULT '0' NOT NULL auto_increment,
  nasname varchar(128),
  shortname varchar(32),
  ipaddr varchar(15),
  type varchar(30),
  ports int(5),
  secret varchar(60),
  community varchar(50),
  snmp varchar(10),
  PRIMARY KEY (id)
);

#
# Table structure for table 'radacct'
#
CREATE TABLE radacct (
  RadAcctId bigint(21) DEFAULT '0' NOT NULL auto_increment,
  AcctSessionId varchar(32) DEFAULT '' NOT NULL,
  AcctUniqueId  varchar(32) DEFAULT '' NOT NULL,
  UserName varchar(32) DEFAULT '' NOT NULL,
  Realm varchar(30) DEFAULT '',
  NASIPAddress varchar(15) DEFAULT '' NOT NULL,
  NASPortId int(12),
  NASPortType varchar(32),
  AcctStartTime datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
  AcctStopTime datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
  AcctSessionTime int(12),
  AcctAuthentic varchar(32),
  ConnectInfo_start varchar(32),
  ConnectInfo_stop varchar(32),
  AcctInputOctets int(12),
  AcctOutputOctets int(12),
  CalledStationId varchar(10) DEFAULT '' NOT NULL,
  CallingStationId varchar(10) DEFAULT '' NOT NULL,
  AcctTerminateCause varchar(32) DEFAULT '' NOT NULL,
  ServiceType varchar(32),
  FramedProtocol varchar(32),
  FramedIPAddress varchar(15) DEFAULT '' NOT NULL,
  AcctStartDelay int(12),
  AcctStopDelay int(12),
  PRIMARY KEY (RadAcctId),
  KEY UserName (UserName),
  KEY FramedIPAddress (FramedIPAddress),
  KEY AcctSessionId (AcctSessionId),
  KEY AcctUniqueId (AcctUniqueId),
  KEY AcctStartTime (AcctStartTime),
  KEY AcctStopTime (AcctStopTime),
  KEY NASIPAddress (NASIPAddress)
);

#
# Table structure for table 'radcheck'
#
CREATE TABLE radcheck (
  id int(10) DEFAULT '0' NOT NULL auto_increment,
  UserName varchar(30) DEFAULT '' NOT NULL,
  Attribute varchar(30),
  Value varchar(40),
  op char(2),
  PRIMARY KEY (id),
  KEY UserName (UserName)
);

#
# Table structure for table 'radgroupcheck'
#
CREATE TABLE radgroupcheck (
  id int(10) DEFAULT '0' NOT NULL auto_increment,
  GroupName varchar(20) DEFAULT '' NOT NULL,
  Attribute varchar(40),
  Value varchar(40),
  op char(2),
  PRIMARY KEY (id),
  KEY GroupName (GroupName)
);

#
# Table structure for table 'radgroupreply'
#
CREATE TABLE radgroupreply (
  id int(10) DEFAULT '0' NOT NULL auto_increment,
  GroupName varchar(20) DEFAULT '' NOT NULL,
  Attribute varchar(40),
  Value varchar(40),
  op char(2),
  PRIMARY KEY (id),
  KEY GroupName (GroupName)
);

#
# Table structure for table 'radreply'
#
CREATE TABLE radreply (
  id int(10) DEFAULT '0' NOT NULL auto_increment,
  UserName varchar(30) DEFAULT '' NOT NULL,
  Attribute varchar(30),
  Value varchar(40),
  op char(2),
  PRIMARY KEY (id),
  KEY UserName (UserName)
);

#
# Table structure for table 'usergroup'
#
CREATE TABLE usergroup (
  id int(10) DEFAULT '0' NOT NULL auto_increment,
  UserName varchar(30) DEFAULT '' NOT NULL,
  GroupName varchar(30),
  PRIMARY KEY (id),
  KEY UserName (UserName)
);

#
# Table structure for table 'realmgroup'
#
CREATE TABLE realmgroup (
  id int(10) DEFAULT '0' NOT NULL auto_increment,
  RealmName varchar(30) DEFAULT '' NOT NULL,
  GroupName varchar(30),
  PRIMARY KEY (id),
  KEY RealmName (RealmName)
);

CREATE TABLE realms (
  id int(10) DEFAULT '0' NOT NULL auto_increment,
  realmname varchar(64),
  nas varchar(128),
  authport int(5),
  options varchar(128) DEFAULT '',
  PRIMARY KEY (id)
);
