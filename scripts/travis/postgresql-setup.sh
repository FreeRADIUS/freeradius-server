#!/bin/sh -e

psql -c 'create database radius;' -U postgres
psql -U postgres radius < raddb/mods-config/sql/main/postgresql/schema.sql
psql -U postgres radius < raddb/mods-config/sql/main/postgresql/setup.sql
psql -c 'GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO radius;' -U postgres radius
