--
-- Table structure for table 'dhcpippool'
--
CREATE TABLE dhcpippool (
  id                    int(11) PRIMARY KEY,
  pool_name             varchar(30) NOT NULL,
  framedipaddress       varchar(15) NOT NULL default '',
  pool_key              varchar(30) NOT NULL default '',
  gatewayipaddress      varchar(15) NOT NULL default '',
  expiry_time           DATETIME NOT NULL default (DATETIME('now'))
);

CREATE INDEX dhcpippool_poolname_expire ON dhcpippool(pool_name, expiry_time);
CREATE INDEX dhcpippool_framedipaddress ON dhcpippool(framedipaddress);
CREATE INDEX dhcpippool_nasip_poolkey_ipaddress ON dhcpippool(pool_name, pool_key, framedipaddress);
