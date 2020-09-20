--
-- Table structure for table 'radippool'
--
CREATE TABLE radippool (
  id                    int(11) PRIMARY KEY,
  pool_name             varchar(30) NOT NULL,
  framedipaddress       varchar(15) NOT NULL default '',
  nasipaddress          varchar(15) NOT NULL default '',
  calledstationid       VARCHAR(30) NOT NULL default '',
  callingstationid      VARCHAR(30) NOT NULL default '',
  expiry_time           DATETIME NOT NULL default (DATETIME('now')),
  username              varchar(64) NOT NULL default '',
  pool_key              varchar(30) NOT NULL default ''
);

CREATE INDEX radippool_poolname_expire ON radippool(pool_name, expiry_time);
CREATE INDEX radippool_framedipaddress ON radippool(framedipaddress);
CREATE INDEX radippool_nasip_poolkey_ipaddress ON radippool(nasipaddress, pool_key, framedipaddress);
