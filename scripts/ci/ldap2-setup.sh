#!/bin/sh

# Allow setup script to work with homebrew too
export PATH="/usr/local/opt/openldap/libexec:$PATH"

# Clean out any existing DB
rm -rf /tmp/ldap2/db
# Create directory we can write DB files to
mkdir -p /tmp/ldap2/db/

# Change db location to /tmp as we can't write to /var
sed -i -e 's/\/var\/lib\/ldap/\/tmp\/ldap2\/db/' src/tests/salt-test-server/salt/ldap/base2.ldif

# Create a directory we can link schema files into
if [ -d /tmp/ldap2/schema ]; then
    echo "Schema dir already linked"
# Debian
elif [ -d /etc/ldap/schema ]; then
    ln -fs /etc/ldap/schema /tmp/ldap2/schema
# Redhat
elif [ -d /etc/openldap/schema ]; then
    ln -fs /etc/openldap/schema /tmp/ldap2/schema
# macOS (homebrew)
elif [ -d /usr/local/etc/openldap/schema ]; then
    ln -fs /usr/local/etc/openldap/schema /tmp/ldap2/schema
else
    echo "Can't locate OpenLDAP schema dir"
    exit 1
fi

# Start slapd
slapd -h "ldap://127.0.0.1:3891/" -f scripts/ci/ldap/slapd2.conf &

# Wait for LDAP to start
sleep 1

# Add test data
count=0
while [ $count -lt 10 ] ; do
    if ldapadd -x -H ldap://127.0.0.1:3891/ -D "cn=admin,cn=config" -w secret -f src/tests/salt-test-server/salt/ldap/base2.ldif ; then
        break 2
    else
        count=$((count+1))
        sleep 1
    fi
done

if [ $? -ne 0 ]; then
        echo "Error configuring server"
        exit 1
fi

