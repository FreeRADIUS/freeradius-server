--
-- Table structure for table 'radippool'
--
-- See also "procedure.sql" in this directory for a stored procedure
-- that is much faster.
--

CREATE TABLE radippool (
  id                    int(11) unsigned NOT NULL auto_increment,
  pool_name             varchar(30) NOT NULL,
  framedipaddress       varchar(15) NOT NULL default '',
  nasipaddress          varchar(15) NOT NULL default '',
  calledstationid       VARCHAR(30) NOT NULL default '',
  callingstationid      VARCHAR(30) NOT NULL default '',
  expiry_time           DATETIME NOT NULL default NOW(),
  username              varchar(64) NOT NULL default '',
  pool_key              varchar(30) NOT NULL default '',
  PRIMARY KEY (id),
  KEY radippool_poolname_expire (pool_name, expiry_time),
  KEY framedipaddress (framedipaddress),
  KEY radippool_poolname_poolkey_ipaddress (pool_name, pool_key, framedipaddress)
) ENGINE=InnoDB;
