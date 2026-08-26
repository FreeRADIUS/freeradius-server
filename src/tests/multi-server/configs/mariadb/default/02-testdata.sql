--
-- Test fixture for the mysql multi-server suite.
--
-- The canonical schema is loaded via a separate mount of
-- raddb/mods-config/sql/main/mysql/schema.sql into
-- /docker-entrypoint-initdb.d/01-schema.sql; this file is mounted as
-- /docker-entrypoint-initdb.d/02-testdata.sql, ordering after the
-- schema so the inserts find their tables.
--
INSERT INTO radcheck (username, attribute, op, value)
VALUES ('testuser', 'Password.Cleartext', ':=', 'testpass');

INSERT INTO radreply (username, attribute, op, value)
VALUES ('testuser', 'Reply-Message', ':=', 'Hello, testuser!');
