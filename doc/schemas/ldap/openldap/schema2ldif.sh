#!/bin/bash

if [ -z "$1" ]; then
  echo "Missing schema file"
  exit 1
fi

SCHEMA_CONV_DIR="$(mktemp -d)"
SCHEMA_IN=$1
SCHEMA_NAME=${SCHEMA_IN%%.*}
SCHEMA_OUT=${SCHEMA_NAME}.ldif

#
#  Add all schemas to convert to a temporary config file
#
cat << EOF > ${SCHEMA_CONV_DIR}/convert.conf
include $1
EOF

mkdir -p ${SCHEMA_CONV_DIR}/out

echo "Converting ${SCHEMA_NAME} ${SCHEMA_IN} -> ${SCHEMA_OUT}"

slapcat -o ldif-wrap=no -f ${SCHEMA_CONV_DIR}/convert.conf -F ${SCHEMA_CONV_DIR}/out -n 0 -H "ldap:///cn={0}${SCHEMA_NAME},cn=schema,cn=config" | sed -re 's/\{[0-9]+\}//' \
  -e '/^structuralObjectClass: /d' -e '/^entryUUID: /d' -e '/^creatorsName: /d' \
  -e '/^createTimestamp: /d' -e '/^entryCSN: /d' -e '/^modifiersName: /d' \
  -e '/^modifyTimestamp: /d' -e '/^$/d' > ${SCHEMA_OUT}

rm -rf ${SCHEMA_CONV_DIR}
