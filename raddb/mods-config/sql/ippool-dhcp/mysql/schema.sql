--
-- Table structure for table 'dhcpippool'
--
-- See also "procedure.sql" in this directory for a stored procedure
-- that is much faster.
--

CREATE TABLE dhcpippool (
	id			int unsigned NOT NULL auto_increment,
	pool_name		varchar(30) NOT NULL,
	framedipaddress		varchar(15) NOT NULL default '',
	pool_key		varchar(30) NOT NULL default '',
	gateway			varchar(15) NOT NULL default '',
	expiry_time		DATETIME NOT NULL default NOW(),
	`status`		ENUM('dynamic', 'static', 'declined', 'disabled') DEFAULT 'dynamic',
	counter			int unsigned NOT NULL default 0,
	PRIMARY KEY (id),
	KEY dhcpippool_poolname_expire (pool_name, expiry_time),
	KEY framedipaddress (framedipaddress),
	KEY dhcpippool_poolname_poolkey_ipaddress (pool_name, pool_key, framedipaddress)
) ENGINE=InnoDB;
