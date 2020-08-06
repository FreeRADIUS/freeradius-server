--
-- Table structure for table 'dhcpippool'
--
-- See also "procedure.sql" in this directory for
-- a stored procedure that gives much faster response.
--

CREATE TABLE dhcpippool (
  id                    int IDENTITY (1,1) NOT NULL,
  pool_name             varchar(30) NOT NULL,
  FramedIPAddress       varchar(15) NOT NULL default '',
  pool_key              varchar(30) NOT NULL default '',
  GatewayIPAddress      varchar(15) NOT NULL default '',
  expiry_time           DATETIME NOT NULL default CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
)
GO

CREATE INDEX dhcp_poolname_expire ON dhcpippool(pool_name, expiry_time)
GO

CREATE INDEX dhcp_FramedIPAddress ON dhcpippool(FramedIPAddress)
GO

CREATE INDEX dhcp_poolname_poolkey_FramedIPAddress ON dhcpippool(pool_name, pool_key, FramedIPAddress)
GO
