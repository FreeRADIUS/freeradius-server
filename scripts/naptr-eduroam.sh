#! /bin/sh

# Example script!
# This script looks up radsec srv records in DNS for the one
# realm given as argument, and creates a server template based
# on that. It currently ignores weight markers, but does sort
# servers on priority marker, lowest number first.
# For host command this is column 5, for dig it is column 1.

usage() {
    echo "Usage: ${0} <realm> <optional NAPTR tag>"
    exit 1
}

test -n "${1}" || usage

DIGCMD=$(command -v dig)
HOSTCMD=$(command -v host)
PRINTCMD=$(command -v printf)
test -n "${2}" && NAPTRTAG="${2}" || NAPTRTAG="x-eduroam:radius.tls"


validate_host() {
         echo ${@} | tr -d '\n\t\r' | grep -E '^[_0-9a-zA-Z][-._0-9a-zA-Z]*$'
}

validate_port() {
         echo ${@} | tr -d '\n\t\r' | grep -E '^[0-9]+$'
}

dig_it_srv() {
    ${DIGCMD} +short srv $SRV_HOST | sort -n -k1 |
    while read line; do
        set $line ; PORT=$(validate_port $3) ; HOST=$(validate_host $4)
        if [ -n "${HOST}" ] && [ -n "${PORT}" ]; then
            $PRINTCMD "\thost ${HOST%.}:${PORT}\n"
        fi
    done
}

dig_it_naptr() {
    ${DIGCMD} +short naptr "${REALM}" | grep $NAPTRTAG | sort -n -k1 |
    while read line; do
        set $line ; TYPE=$3 ; HOST=$(validate_host $6)
        if ( [ "$TYPE" = "\"s\"" ] || [ "$TYPE" = "\"S\"" ] ) && [ -n "${HOST}" ]; then
            SRV_HOST=${HOST%.}
            dig_it_srv
        fi
    done
}

host_it_srv() {
    ${HOSTCMD} -t srv $SRV_HOST | sort -n -k5 |
    while read line; do
        set $line ; PORT=$(validate_port $7) ; HOST=$(validate_host $8) 
        if [ -n "${HOST}" ] && [ -n "${PORT}" ]; then
            $PRINTCMD "\thost ${HOST%.}:${PORT}\n"
        fi
    done
}

host_it_naptr() {
    ${HOSTCMD} -t naptr "${REALM}" | grep $NAPTRTAG | sort -n -k5 |
    while read line; do
        set $line ; TYPE=$7 ; HOST=$(validate_host ${10})
        if ( [ "$TYPE" = "\"s\"" ] || [ "$TYPE" = "\"S\"" ] ) && [ -n "${HOST}" ]; then
            SRV_HOST=${HOST%.}
            host_it_srv
        fi
    done
}

REALM=$(validate_host ${1})
if [ -z "${REALM}" ]; then
    echo "Error: realm \"${1}\" failed validation"
    usage
fi

if [ -x "${DIGCMD}" ]; then
    SERVERS=$(dig_it_naptr)
elif [ -x "${HOSTCMD}" ]; then
    SERVERS=$(host_it_naptr)
else
    echo "${0} requires either \"dig\" or \"host\" command."
    exit 1
fi

if [ -n "${SERVERS}" ]; then
    $PRINTCMD "server dynamic_radsec.${REALM} {\n${SERVERS}\n}\n"
    exit 0
fi

exit 10				# No server found.
