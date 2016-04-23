#!/bin/sh -e

echo "PostgreSQL - Creating database"
psql -h "${SQL_POSTGRESQL_TEST_SERVER}" -c 'create database radius;' -U postgres

echo "PostgreSQL - Execute schema.sql"
psql -h "${SQL_POSTGRESQL_TEST_SERVER}" -U postgres radius < raddb/mods-config/sql/main/postgresql/schema.sql

echo "PostgreSQL - Execute setup.sql"
psql -h "${SQL_POSTGRESQL_TEST_SERVER}" -U postgres radius < raddb/mods-config/sql/main/postgresql/setup.sql

echo "PostgreSQL - Grant radius user permissions"
psql -h "${SQL_POSTGRESQL_TEST_SERVER}" -c 'GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO radius;' -U postgres radius
