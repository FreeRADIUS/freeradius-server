SET search_path = public, pg_catalog;

--Table structure for table 'badusers'
--
CREATE TABLE badusers (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    date timestamp with time zone DEFAULT 'now' NOT NULL,
    reason TEXT,
    admin TEXT DEFAULT '-'
);
CREATE INDEX badusers_actiondate_idx ON badusers USING btree (actiondate);
CREATE INDEX badusers_username_idx ON badusers USING btree (username);
