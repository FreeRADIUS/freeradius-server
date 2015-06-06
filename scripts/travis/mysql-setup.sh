#!/bin/sh -e

mysql -u root -e 'CREATE DATABASE radius;'
mysql -u root radius < raddb/mods-config/sql/main/mysql/schema.sql
mysql -u root radius < raddb/mods-config/sql/main/mysql/setup.sql
mysql -u root -e 'GRANT ALL on radius.* TO radius@localhost;'
