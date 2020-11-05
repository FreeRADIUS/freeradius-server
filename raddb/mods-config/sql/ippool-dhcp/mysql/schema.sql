#
# Table structure for table 'fr_ippool'
#
CREATE TABLE fr_ippool (
	id			int unsigned NOT NULL auto_increment,
	pool_name		varchar(30) NOT NULL,
	address		        varchar(15) NOT NULL DEFAULT '',
	owner		        varchar(128) NOT NULL DEFAULT '',
	gateway			varchar(128) NOT NULL DEFAULT '',
	expiry_time		DATETIME NOT NULL DEFAULT NOW(),
	status			ENUM('dynamic', 'static', 'declined', 'disabled') DEFAULT 'dynamic',
	counter			int unsigned NOT NULL DEFAULT 0,
	PRIMARY KEY (id),
	KEY fr_ippool_poolname_expire (pool_name, expiry_time),
	KEY address (address),
	KEY fr_ippool_poolname_poolkey_ipaddress (pool_name, owner, address)
) ENGINE=InnoDB;
