SET search_path = public, pg_catalog;

--
-- Table structure for table 'userinfo'
--
CREATE TABLE userinfo (
    id SERIAL PRIMARY KEY,
    username TEXT,
    name TEXT,
    mail TEXT,
    department TEXT,
    workphone TEXT,
    homephone TEXT,
    mobile TEXT
);
CREATE INDEX userinfo_department_idx ON userinfo USING btree (department);
CREATE INDEX userinfo_username_idx ON userinfo USING btree (username);


