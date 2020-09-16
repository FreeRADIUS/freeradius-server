--
-- Table structure for table 'radippool'
--
CREATE TABLE radippool (
  id                    int IDENTITY (1,1) NOT NULL,
  pool_name             varchar(30) NOT NULL,
  FramedIPAddress       varchar(15) NOT NULL default '',
  NASIPAddress          varchar(15) NOT NULL default '',
  CalledStationId       VARCHAR(32) NOT NULL default '',
  CallingStationId      VARCHAR(30) NOT NULL default '',
  expiry_time           DATETIME NOT NULL default CURRENT_TIMESTAMP,
  UserName              varchar(64) NOT NULL default '',
  pool_key              varchar(30) NOT NULL default '',
  PRIMARY KEY (id)
)
GO

CREATE INDEX poolname_expire ON radippool(pool_name, expiry_time)
GO

CREATE INDEX FramedIPAddress ON radippool(FramedIPAddress)
GO

CREATE INDEX NASIPAddress_poolkey_FramedIPAddress ON radippool(NASIPAddress, pool_key, FramedIPAddress)
GO
