#!/bin/sh

set -e

export RANDFILE=/dev/null

base_dir=$(dirname $0)/../../../raddb/certs

# A POSIX variable
OPTIND=1         # Reset in case getopts has been used previously in the shell.

while getopts "b:c:C:e:s:l:o:" opt; do
    case "$opt" in
    b)
        base_dir=$OPTARG
        ;;

    c)
        common_name=$OPTARG
        ;;

    C)
        country=$OPTARG
        ;;

    e)
        email=$OPTARG
        ;;

    s)
        state=$OPTARG
        ;;

    l)
        locality_name=$OPTARG
        ;;

    o)
        organization_name=$OPTARG
        ;;
    esac
done

cd "$base_dir"

password=$(grep output_password server.cnf | sed 's/.*=//;s/^ *//')

name=$(echo "${country}${state}${locality_name}${organization_name}${email}${common_name}" | openssl md5 | grep -E -o '[0-9a-f]+$')

#
#  Create a temporary configuration file (-subj arg doesn't
#  seem to work).
#
cp server.cnf "$name.cnf"
if [ ! -z "$country" ]; then
    sed -i '' -e "s/^countryName.*/countryName=$country/" "$name.cnf"
fi

if [ ! -z "$state" ]; then
    sed -i '' -e "s/^stateOrProvinceName.*/stateOrProvinceName=$state/" "$name.cnf"
fi

if [ ! -z "$locality_name" ]; then
    sed -i '' -e "s/^localityName.*/localityName=$locality_name/" "$name.cnf"
fi

if [ ! -z "$organization_name" ]; then
    sed -i '' -e "s/^organizationName.*/organizationName=$organization_name/" "$name.cnf"
fi

if [ ! -z "$common_name" ]; then
    sed -i '' -e "s/^commonName.*/commonName=$common_name/" "$name.cnf"
fi

if [ ! -z "$email" ]; then
    sed -i '' -e "s/^emailAddress.*/emailAddress=$email/" "$name.cnf"
fi

#
#  Generate a new CSR, using same private key for speed
#
openssl req -new -out "${name}.csr" -key server.key -config "${name}.cnf" 2> /dev/null
rm "${name}.cnf"

#
#  Sign the CSR with the existing CA
#
#  x509 command allows us to do it without maintaining a database.
#
openssl x509 -req -CAkey "ca.key" -CA "ca.pem" -in "${name}.csr" -passin pass:${password} -out "${name}.crt" \
    -CAcreateserial -extensions xpserver_ext -extfile xpextensions 2> /dev/null
rm "${name}.csr"
rm "ca.srl"

#
#  Export signed certificate as p12
#
openssl pkcs12 -export -in "${name}.crt" -inkey server.key -out "${name}.p12" -passin pass:${password} -passout pass:${password} 2> /dev/null

#
#  Export signed certificate as pem
#
openssl pkcs12 -in "${name}.p12" -out "${name}.pem" -passin pass:${password} -passout pass:${password} 2> /dev/null

echo "${name}"
