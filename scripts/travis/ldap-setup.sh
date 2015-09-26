#!/bin/sh -e

# Create directory we can write DB files to
mkdir /tmp/ldap_db/

# Change db location to /tmp as we can't write to /var
sed -i 's/\/var\/lib\/ldap/\/tmp\/ldap_db/' src/tests/salt-test-server/salt/ldap/base.ldif

# Start slapd as travis user
/usr/sbin/slapd -h "ldap://127.0.0.1:3890/" -f scripts/travis/ldap/slapd.conf

# Wait for LDAP to start
sleep 1

# Add test data
ldapadd -x -H ldap://127.0.0.1:3890/ -D "cn=admin,cn=config" -w secret -f src/tests/salt-test-server/salt/ldap/base.ldif
