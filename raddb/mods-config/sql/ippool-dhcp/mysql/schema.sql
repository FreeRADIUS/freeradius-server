#
# Table structure for table 'dhcpippool'
#
CREATE TABLE dhcpippool (
	id			int(11) unsigned NOT NULL auto_increment,
	pool_name		varchar(30) NOT NULL,
	framedipaddress		varchar(15) NOT NULL DEFAULT '',
	pool_key		varchar(30) NOT NULL DEFAULT '',
	gatewayipaddress	varchar(15) NOT NULL DEFAULT '',
	expiry_time		DATETIME NOT NULL DEFAULT NOW(),
	status			ENUM('dynamic', 'static', 'declined', 'disabled') DEFAULT 'dynamic',
	PRIMARY KEY (id),
	KEY dhcpippool_poolname_expire (pool_name, expiry_time),
	KEY framedipaddress (framedipaddress),
	KEY dhcpippool_poolname_poolkey_ipaddress (pool_name, pool_key, framedipaddress)
) ENGINE=InnoDB;
