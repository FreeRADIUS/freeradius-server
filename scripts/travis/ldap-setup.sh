#!/bin/sh

# Allow setup script to work with homebrew too
export PATH="/usr/local/opt/openldap/libexec:$PATH"

# Create directory we can write DB files to
mkdir -p /tmp/ldap/db/

# Change db location to /tmp as we can't write to /var
sed -i -e 's/\/var\/lib\/ldap/\/tmp\/ldap\/db/' src/tests/salt-test-server/salt/ldap/base.ldif

# Create a directory we can link schema files into
if [ -d /tmp/ldap/schema ]; then
    echo "Schema dir already linked"
# Debian
elif [ -d /etc/ldap/schema ]; then
    ln -fs /etc/ldap/schema /tmp/ldap/schema
# Redhat
elif [ -d /etc/openldap/schema ]; then
    ln -fs /etc/openldap/schema /tmp/ldap/schema
# macOS (homebrew)
elif [ -d /usr/local/etc/openldap/schema ]; then
    ln -fs /usr/local/etc/openldap/schema /tmp/ldap/schema
else
    echo "Can't locate OpenLDAP schema dir"
    exit 1
fi

# Start slapd
slapd -h "ldap://127.0.0.1:3890/" -f scripts/travis/ldap/slapd.conf &

# Wait for LDAP to start
sleep 1

# Add test data
ldapadd -x -H ldap://127.0.0.1:3890/ -D "cn=admin,cn=config" -w secret -f src/tests/salt-test-server/salt/ldap/base.ldif
if [ $? -ne 0 ]; then
	echo "Error configuring server"
	exit 1
fi
