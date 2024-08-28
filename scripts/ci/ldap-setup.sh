#!/usr/bin/env bash

urlencode() {
    local string="${1}"
    local strlen=${#string}
    local encoded=""
    local pos c o

    for (( pos=0 ; pos<strlen ; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9] )
                o="${c}" ;;
            *)
                printf -v o '%%%02x' "'$c"
        esac
        encoded+="${o}"
    done
    echo "${encoded}"
}

VERBOSE=true
error () {
    echo "$@" 1>&2
}

debug () {
    if $VERBOSE; then
        echo "$@"
    fi
}

# Allow setup script to work with homebrew too
export PATH="/usr/local/opt/openldap/libexec:/opt/homebrew/opt/openldap/libexec:/opt/symas/lib:$PATH"

suffix=$(echo "${0##*/}" | sed -E 's/^ldap(.*)-setup.sh$/\1/')

# Kill any old processes
[ -e "/tmp/slapd${suffix}.pid" ] && kill $(cat /tmp/slapd${suffix}.pid)

# Set the default basedir based on the suffix of $0
base_dir="/tmp/ldap${suffix}"

# Default FreeRADIUS schemas
default_aux_schema_src=(
    "doc/schemas/ldap/openldap/freeradius-policy.schema"
    "doc/schemas/ldap/openldap/freeradius-radius.schema"
    "doc/schemas/ldap/openldap/freeradius-clients.schema"
)

# Start with no aux schemas, if the user doesn't specify any we copy the default schemas
aux_schema_src=()

#
# Command line options to override the default template values
#
while getopts 'b:s:S:' opt; do
    case "$opt" in
    b)
        base_dir="$OPTARG"
        ;;

    s)
        socket_path="$OPTARG"
        ;;

    S)
        schema_src+=("$OPTARG")
        ;;

    *)
        error "Usage: $0 [-b base_dir] [-s socket_path] [-S schema_src]"
        exit 1
        ;;
    esac
done
shift "$(($OPTIND -1))"

cert_dir="${base_dir}/certs"
data_dir="${base_dir}/db"
schema_dir="${base_dir}/schema"
[ -z ${socket_path+x} ] && socket_path="${base_dir}/socket"
[ ${#aux_schema_src[@]} -eq 0 ] && aux_schema_src=(${default_aux_schema_src[*]})

socket_url=ldapi://$(urlencode "${socket_path}")

debug "base_dir \"${base_dir}\""

# Clean out any existing data
rm -rf "${data_dir}"

# Clean out any old certificates
rm -rf "${cert_dir}"

# Create the base dir
mkdir -p "${base_dir}" || exit $?

# Create directory for certs
mkdir -p "${cert_dir}" || exit $?

# Create directory we can write DB files to
mkdir -p "${data_dir}" || exit $?

# Change db location to /tmp as we can't write to /var
sed -i -e "s/\/var\/lib\/ldap/\/tmp\/ldap${suffix}\/db/" src/tests/salt-test-server/salt/ldap/base${suffix}.ldif

# Create a directory we can link schema files into
mkdir -p "${schema_dir}" || exit $?

# Debian
if [ -d /etc/ldap/schema ]; then
    schema_src_dir="/etc/ldap/schema"
# Symas packages
elif [ -d /opt/symas/etc/openldap/schema ]; then
    schema_src_dir="/opt/symas/etc/openldap/schema"
# Redhat
elif [ -d /etc/openldap/schema ]; then
    schema_src_dir="/etc/openldap/schema"
# macOS (homebrew x86)
elif [ -d /usr/local/etc/openldap/schema ]; then
    schema_src_dir="/usr/local/etc/openldap/schema"
# macOS (homebrew ARM)
elif [ -d /opt/homebrew/opt/openldap/schema ]; then
    schema_src_dir="/opt/homebrew/opt/openldap/schema"
else
    echo "Can't locate OpenLDAP schema dir"
    exit 1
fi

# Copy all schemas over to the schema dir, so they're all available for inclusion
# we don't overwrite any existing files to avoid overwriting developer changes.
for i in ${schema_src_dir}/*; do
    # Only copy in schema files that don't already exist
    cp -n "${i}" "${schema_dir}/"
done

# Copy over the auxiliary schemas
for i in "${aux_schema_src[@]}" ; do
    cp -n "${i}" "${schema_dir}/"
done

# Ensure we have some certs generated
make -C raddb/certs

# Copy certificates - whilst not stricltly LDAP certs they work fine for these tests
cp raddb/certs/rsa/ca.pem "${cert_dir}/cacert.pem"
cp raddb/certs/rsa/server.pem "${cert_dir}/servercert.pem"
openssl rsa -in raddb/certs/rsa/server.key -out "${cert_dir}/serverkey.pem" -passin pass:whatever

ldap_bind_ip="127.0.0.1"
if [ -z "${suffix}" ]; then
    ldap_port="3890"
    ldaps_port="6360"
else
    ldap_port=$((3890+${suffix}))
    ldaps_port=$((6360+${suffix}))
fi

# Copy the config over to the base_dir.  There seems to be some issues with actions runners
# not allowing file access outside of /etc/ldap, so we copy the config to the specified base_dir.
cp -n "scripts/ci/ldap/slapd${suffix}.conf" "${base_dir}/slapd.conf"

# Start slapd
slapd -d any -h "ldap://${ldap_bind_ip}:${ldap_port}/ ldaps://${ldap_bind_ip}:${ldaps_port}/ ${socket_url}" -f "${base_dir}/slapd.conf" > ${base_dir}/slapd.log 2>&1 &

# Wait for LDAP to start
sleep 1

# Add test data
count=0
while [ $count -lt 10 ] ; do
    if ldapadd -v -x -H "${socket_url}" -D "cn=admin,cn=config" -w secret -f src/tests/salt-test-server/salt/ldap/base${suffix}.ldif ; then
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

echo "Listening on ldap://${ldap_bind_ip}:${ldap_port}/ ldaps://${ldap_bind_ip}:${ldaps_port}/ ${socket_url}"
cat << EOF
export LDAP_TEST_SERVER=${ldap_bind_ip}
export LDAP_TEST_SERVER_PORT=${ldap_port}
export LDAP_TEST_SERVER_SSL_PORT=${ldaps_port}
EOF
