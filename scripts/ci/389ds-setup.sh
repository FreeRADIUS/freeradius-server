#!/bin/sh

# Build template config file
cat <<EOF > /tmp/instance.inf
[general]
config_version = 2

[slapd]
root_dn = cn=manager
root_password = secret123
port = 3892
secure_port = 6362
self_sign_cert = True

[backend-userroot]
suffix = dc=example,dc=com
sample_entries = yes
require_index = yes
EOF

# Initialise ds instance from config
sudo dscreate from-file /tmp/instance.inf

# Load base entries
count=0
while [ $count -lt 10 ] ; do
    if ldapadd -x -H ldap://127.0.0.1:3892/ -D "cn=manager" -w "secret123" -f src/tests/salt-test-server/salt/ldap/base3.ldif ; then
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
