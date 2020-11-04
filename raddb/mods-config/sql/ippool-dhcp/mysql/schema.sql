#
# Table structure for table 'dhcpippool'
#
CREATE TABLE dhcpippool (
	id			int unsigned NOT NULL auto_increment,
	pool_name		varchar(30) NOT NULL,
	address		varchar(15) NOT NULL DEFAULT '',
	pool_key		varchar(30) NOT NULL DEFAULT '',
	gateway			varchar(15) NOT NULL DEFAULT '',
	expiry_time		DATETIME NOT NULL DEFAULT NOW(),
	status			ENUM('dynamic', 'static', 'declined', 'disabled') DEFAULT 'dynamic',
	counter			int unsigned NOT NULL DEFAULT 0,
	PRIMARY KEY (id),
	KEY dhcpippool_poolname_expire (pool_name, expiry_time),
	KEY address (address),
	KEY dhcpippool_poolname_poolkey_ipaddress (pool_name, pool_key, address)
) ENGINE=InnoDB;
