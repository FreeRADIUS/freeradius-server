#
# Table structure for table 'userinfo'
#
CREATE TABLE userinfo (
  id int(10) DEFAULT '0' NOT NULL auto_increment,
  UserName varchar(30),
  Name varchar(200),
  Mail varchar(200),
  Department varchar(200),
  WorkPhone varchar(200),
  HomePhone varchar(200),
  Mobile varchar(200),
  PRIMARY KEY (id),
  KEY UserName (UserName),
  KEY Department (Department)
);
