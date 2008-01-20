#
# Table structure for table 'badusers'
#
CREATE TABLE badusers (
  id int(10) NOT NULL auto_increment,
  UserName varchar(30),
  IncidentDate	datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
  Reason varchar(200),
  Admin varchar(30) DEFAULT '-',
  PRIMARY KEY (id),
  KEY UserName (UserName),
  KEY IncidentDate (IncidentDate)
);
