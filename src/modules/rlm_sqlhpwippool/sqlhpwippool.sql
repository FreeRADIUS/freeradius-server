---
--- SQL schema for rlm_sqlhpwippool
---

-- CREATE DATABASE netvim DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;
-- USE netvim;

CREATE TABLE gid_ip (
  gid int NOT NULL CHECK (gid > 0) default '0' PRIMARY KEY,
  ip_start bigint NOT NULL CHECK (ip_start > 0) default '0',
  ip_stop bigint NOT NULL CHECK (ip_stop > 0) default '0'
);
--COMMENT ON TABLE gid_ip IS 'Netvim: host groups to IP ranges relations';

CREATE TABLE host_groups (
  gid int NOT NULL CHECK (gid > 0) default '0' PRIMARY KEY,
  parent int default NULL CHECK (parent > 0),
  name varchar(128) NOT NULL default ''
);
CREATE UNIQUE INDEX group_name ON host_groups (name);
--COMMENT ON TABLE host_groups IS 'Netvim: host groups';

CREATE TABLE ids (
  id SERIAL,
  enabled BOOLEAN NOT NULL default '1',
  modified TIMESTAMP NOT NULL default '0',
  created TIMESTAMP NOT NULL default '0',
  type varchar(64) default NULL,
  PRIMARY KEY (id)
);
--COMMENT ON TABLE ids IS 'Entity: the source of ID numbers';

CREATE TABLE ip_pools (
  pid int NOT NULL CHECK (pid > 0) default '0' COMMENT 'Named pool ID',
  gid int NOT NULL CHECK (gid > 0) default '0' COMMENT 'Host group ID',
  pnid int NOT NULL CHECK (pnid > 0) default '0' COMMENT 'Pool name ID',
  ip_start bigint NOT NULL CHECK (ip_start > 0) default '0' COMMENT 'Beginning of IP range',
  ip_stop bigint NOT NULL CHECK (ip_stop > 0) default '0' COMMENT 'End of IP range',
  prio int NOT NULL default '0' COMMENT 'Pool priority',
  weight int unsigned NOT NULL default '1' COMMENT 'Pool weight',
  total bigint unsigned NOT NULL default '0' COMMENT 'Total number of IPs in pool',
  free bigint unsigned NOT NULL default '0' COMMENT 'Number of free IPs in pool',
  PRIMARY KEY (pid),
  KEY gid (gid,pnid)
);
-- ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='Netvim: named IP pools assigned to given host group';

CREATE TABLE ips (
  ip bigint unsigned NOT NULL default '0' COMMENT 'IP address',
  pid int NOT NULL CHECK (pid > 0) default '0' COMMENT 'Named pool ID',
  rsv_since TIMESTAMP NOT NULL default '0000-00-00 00:00:00' COMMENT 'Time when IP was reserved',
  rsv_by varchar(64) default NULL COMMENT 'Who/what reserved IP',
  rsv_until TIMESTAMP NOT NULL default '0000-00-00 00:00:00' COMMENT 'Reservation timeout',
  PRIMARY KEY (ip),
  KEY pid (pid)
);
-- ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='Netvim: states of single IP addresses';

CREATE TABLE pool_names (
  pnid int NOT NULL CHECK (pnid > 0) default '0' COMMENT 'Named pool ID',
  name varchar(128) NOT NULL default '' COMMENT 'Pool UNIX name',
  PRIMARY KEY (pnid),
  UNIQUE KEY pool_name (name)
);
-- ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='Netvim: definitions of pool names';
