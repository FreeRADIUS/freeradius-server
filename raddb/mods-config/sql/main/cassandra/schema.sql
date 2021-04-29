--------------------------------------------------------------------------
-- $Id$                      --
--                                                                      --
--  schema.sql                       rlm_sql - FreeRADIUS SQL Module    --
--                                                                      --
--     Database schema for Cassandra rlm_sql module                     --
--                                                                      --
--------------------------------------------------------------------------

-- Load with:
--	cqlsh --debug -file schema.sql

--
-- Table structure for table 'radacct'
--
CREATE KEYSPACE radius WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };
USE radius;

CREATE TABLE radacct (
  acctuniqueid text,
  acctsessionid text,
  username text,
  groupname text,
  realm text,
  nasipaddress text,
  nasportid text,
  nasporttype text,
  acctstarttime timestamp,
  acctupdatetime timestamp,
  acctstoptime timestamp,
  acctauthentic text,
  connectinfo_start text,
  connectinfo_stop text,
  acctinputoctets bigint,
  acctoutputoctets bigint,
  calledstationid text,
  callingstationid text,
  servicetype text,
  acctterminatecause text,
  framedprotocol text,
  framedipaddress text,
  framedipv6address text,
  framedipv6prefix text,
  framedinterfaceid text,
  delegatedipv6prefix text,
  class text,
  PRIMARY KEY (acctuniqueid)
);

CREATE INDEX ON radacct(username);
CREATE INDEX ON radacct(framedipaddress);
CREATE INDEX ON radacct(framedipv6address);
CREATE INDEX ON radacct(framedipv6prefix);
CREATE INDEX ON radacct(framedinterfaceid);
CREATE INDEX ON radacct(delegatedipv6prefix);
CREATE INDEX ON radacct(nasipaddress);

--
-- Because cassandra doesn't allow secondary indexes to be used in update statements
-- applying acct on/off packets must be done outside of the server, by a script that
-- first performs a SELECT to identify candidate rows, then closes out the sessions.
--
CREATE TABLE radnasreboot (
  nasipaddress text,
  timestamp bigint,
  PRIMARY KEY (timestamp, nasipaddress)
);

CREATE TABLE radpostauth (
  username text,
  pass text,
  reply text,
  authdate timestamp,
  PRIMARY KEY (username, authdate)
) WITH CLUSTERING ORDER BY (authdate ASC);

CREATE TABLE radcheck (
  id uuid,
  username text,
  attribute text,
  op text,
  value text,
  PRIMARY KEY ((username), id, attribute)
);

CREATE TABLE radreply (
  id uuid,
  username text,
  attribute text,
  op text,
  value text,
  PRIMARY KEY ((username), id, attribute)
);

CREATE TABLE radgroupcheck (
  id uuid,
  groupname text,
  attribute text,
  op text,
  value text,
  PRIMARY KEY ((groupname), id, attribute)
);

CREATE TABLE radgroupreply (
  id uuid,
  groupname text,
  attribute text,
  op text,
  value text,
  PRIMARY KEY ((groupname), id, attribute)
);

CREATE TABLE radusergroup (
  username text,
  priority int,
  groupname text,
  PRIMARY KEY (username, priority)
) WITH CLUSTERING ORDER BY (priority ASC);

CREATE TABLE nas (
  id uuid PRIMARY KEY,
  nasname text,
  shortname text,
  type text,
  ports int,
  secret text,
  server text,
  community text,
  description text
);
CREATE INDEX ON nas(nasname);
