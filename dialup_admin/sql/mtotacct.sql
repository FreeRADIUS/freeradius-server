CREATE TABLE mtotacct (
  MTotAcctId bigint(21) NOT NULL auto_increment,
  UserName varchar(64) NOT NULL default '',
  AcctDate date NOT NULL default '0000-00-00',
  ConnNum bigint(12) default NULL,
  ConnTotDuration bigint(12) default NULL,
  ConnMaxDuration bigint(12) default NULL,
  ConnMinDuration bigint(12) default NULL,
  InputOctets bigint(12) default NULL,
  OutputOctets bigint(12) default NULL,
  NASIPAddress varchar(15) default NULL,
  PRIMARY KEY  (MTotAcctId),
  KEY UserName (UserName),
  KEY AcctDate (AcctDate),
  KEY UserOnDate (UserName,AcctDate),
  KEY NASIPAddress (NASIPAddress)
);
