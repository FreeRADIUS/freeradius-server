#!/usr/bin/env bash

# Allow setup script to work with homebrew too
export PATH="/usr/local/opt/openldap/libexec:/opt/homebrew/opt/openldap/libexec:/opt/symas/lib:$PATH"

suffix=$(echo "${0##*/}" | sed -E 's/^ldap(.*)-setup.sh$/\1/')

# Kill any old processes
[ -e "/tmp/slapd${suffix}.pid" ] && kill $(cat /tmp/slapd${suffix}.pid)

base_dir="/tmp/ldap${suffix}"
cert_dir="${base_dir}/certs"
data_dir="${base_dir}/db"
schema_dir="${base_dir}/schema"

echo "base_dir \"${data_dir}\""

# Clean out any existing DB
rm -rf "${data_dir}"
# Create directory we can write DB files to
mkdir -p "${data_dir}"

# Change db location to /tmp as we can't write to /var
sed -i -e "s/\/var\/lib\/ldap/\/tmp\/ldap${suffix}\/db/" src/tests/salt-test-server/salt/ldap/base${suffix}.ldif

# Create a directory we can link schema files into
if [ -d "${schema_dir}" ]; then
    echo "Schema dir already linked"
# Debian
elif [ -d /etc/ldap/schema ]; then
    ln -fs /etc/ldap/schema "${schema_dir}"
# Symas packages
elif [ -d /opt/symas/etc/openldap/schema ]; then
    ln -fs /opt/symas/etc/openldap/schema "${schema_dir}"
# Redhat
elif [ -d /etc/openldap/schema ]; then
    ln -fs /etc/openldap/schema "${schema_dir}"
# macOS (homebrew x86)
elif [ -d /usr/local/etc/openldap/schema ]; then
    ln -fs /usr/local/etc/openldap/schema "${schema_dir}"
# macOS (homebrew ARM)
elif [ -d /opt/homebrew/opt/openldap/schema ]; then
    ln -fs /opt/homebrew/opt/openldap/schema "${schema_dir}"
else
    echo "Can't locate OpenLDAP schema dir"
    exit 1
fi

# Clean out any old certificates
rm -rf "${cert_dir}"
# Create certificate directory
mkdir -p "${cert_dir}"
# Ensure we have some certs generated
make -C raddb/certs

# Copy certificates - whilst not stricltly LDAP certs they work fine for these tests
cp raddb/certs/rsa/ca.pem "${cert_dir}/cacert.pem"
cp raddb/certs/rsa/server.pem "${cert_dir}/servercert.pem"
openssl rsa -in raddb/certs/rsa/server.key -out "${cert_dir}/serverkey.pem" -passin pass:whatever

if [ -z "${suffix}" ]; then
    ldap_port="3890"
    ldaps_port="6360"
    ldap_socket="ldapi://%2Ftmp%2Fldap%2Fsocket"
else
    ldap_port=$((3890+${suffix}))
    ldaps_port=$((6360+${suffix}))
    ldap_socket="ldapi://%2Ftmp%2Fldap${suffix}%2Fsocket"
fi

# Start slapd
slapd -d any -h "ldap://127.0.0.1:${ldap_port}/ ldaps://127.0.0.1:${ldaps_port}/ ${ldap_socket}" -f scripts/ci/ldap/slapd${suffix}.conf 2>&1 > ${base_dir}/slapd.log &

# Wait for LDAP to start
sleep 1

# Add test data
count=0
while [ $count -lt 10 ] ; do
    if ldapadd -v -x -H "${ldap_socket}" -D "cn=admin,cn=config" -w secret -f src/tests/salt-test-server/salt/ldap/base${suffix}.ldif ; then
        break 2
    else
        echo "ldap add failed, retrying..."
        count=$((count+1))
        sleep 1
    fi
done

# Exit code gets overwritten, so we check for failure using count
if [ $count -eq 10 ]; then
    echo "Error configuring server"
    cat ${base_dir}/slapd.log
    exit 1
fi
