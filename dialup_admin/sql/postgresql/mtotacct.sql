SET search_path = public, pg_catalog;

--
-- Table structure for table 'mtotacct'
--
CREATE TABLE mtotacct (
    mtotacctid BIGSERIAL PRIMARY KEY,
    username TEXT DEFAULT '' NOT NULL,
    acctdate DATE DEFAULT 'now' NOT NULL,
    connnum BIGINT,
    conntotduration BIGINT,
    connmaxduration BIGINT,
    connminduration BIGINT,
    inputoctets BIGINT,
    outputoctets BIGINT,
    nasipaddress INET
);
CREATE INDEX mtotacct_acctdate_idx ON mtotacct USING btree (acctdate);
CREATE INDEX mtotacct_nasipaddress_idx ON mtotacct USING btree
(nasipaddress);
CREATE INDEX mtotacct_username_idx ON mtotacct USING btree (username);
CREATE INDEX mtotacct_userondate_idx ON mtotacct USING btree (username,
acctdate);
