SET search_path = public, pg_catalog;

--Table structure for table 'badusers'
--
CREATE TABLE badusers (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    incidentdate timestamp with time zone DEFAULT 'now' NOT NULL,
    reason TEXT,
    admin TEXT DEFAULT '-'
);
CREATE INDEX badusers_incidentdate_idx ON badusers USING btree (incidentdate);
CREATE INDEX badusers_username_idx ON badusers USING btree (username);
