#!/bin/sh -e

echo "MySQL - Dropping existing database"
mysql -h "${SQL_MYSQL_TEST_SERVER}" -u root -e 'DROP DATABASE radius;' || true

echo "MySQL - Dropping existing user"
mysql -h "${SQL_MYSQL_TEST_SERVER}" -u root -e 'DROP USER radius@localhost;' || true

echo "MySQL - Creating database"
mysql -h "${SQL_MYSQL_TEST_SERVER}" -u root -e 'CREATE DATABASE radius;'

echo "MySQL - Executing schema.sql"
mysql -h "${SQL_MYSQL_TEST_SERVER}" -u root radius < raddb/mods-config/sql/main/mysql/schema.sql

echo "MySQL - Executing setup.sql"
mysql -h "${SQL_MYSQL_TEST_SERVER}" -u root radius < raddb/mods-config/sql/main/mysql/setup.sql

echo "MySQL - Grant radius user permissions"
mysql -h "${SQL_MYSQL_TEST_SERVER}" -u root -e "GRANT ALL on radius.* TO radius@localhost; FLUSH PRIVILEGES;"
