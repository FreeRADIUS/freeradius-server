SET search_path = public, pg_catalog;

--
-- Table structure for table 'totacct'
--
CREATE TABLE totacct (
    totacctid bigSERIAL PRIMARY KEY,
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
CREATE INDEX totacct_acctdate_idx ON totacct USING btree (acctdate);
CREATE INDEX totacct_nasipaddress_idx ON totacct USING btree (nasipaddress);
CREATE INDEX totacct_nasondate_idx ON totacct USING btree (acctdate,
nasipaddress);
CREATE INDEX totacct_username_idx ON totacct USING btree (username);
CREATE INDEX totacct_userondate_idx ON totacct USING btree (username,
acctdate);
