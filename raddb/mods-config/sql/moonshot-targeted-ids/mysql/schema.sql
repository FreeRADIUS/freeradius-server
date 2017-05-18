CREATE TABLE `moonshot_targeted_ids` (
  `gss_acceptor` varchar(254) NOT NULL default '',
  `namespace` varchar(36) NOT NULL default '',
  `username` varchar(64) NOT NULL default '',
  `targeted_id` varchar(128) NOT NULL default '',
  `creationdate` timestamp NOT NULL default CURRENT_TIMESTAMP,
  PRIMARY KEY  (`username`,`gss_acceptor`,`namespace`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
