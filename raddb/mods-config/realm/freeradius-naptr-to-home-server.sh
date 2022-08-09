#!/bin/sh

#  This script looks up radsec srv records in DNS for the one realm
#  given as argument, and creates a home_server template based on the
#  information found.
#
#  It currently ignores weight markers, but does sort servers on
#  priority marker, lowest number first.  For host command this is
#  column 5, for dig it is column 1.
#
#  It then tells FreeRADIUS (via radmin) that
#  there is a new home server.
#
#  Note that in order for it to work, you need to have the
#  "control-socket" enabled.

usage() {
	echo "Usage: ${0} [OPTIONS] <realm> <optional NAPTR tag>"
	echo "        -d RADIUS_DIR       Set radius directory"
	echo "        -t                  test (skip running radmin)"
	exit 1
}

test -n "${1}" || usage

RADDB=/etc/raddb
RADMIN=y

#
#  Parse command-line options
#
while [ `echo "$1" | cut -c 1` = "-" ]
do
   case "$1" in
	-d) 
		RADDB=$2
		shift;shift
		;;
	-t)
		RADMIN=
		shift
		;;

	*)
		usage
		;;
  esac
done

test -n "${2}" && NAPTRTAG="${2}" || NAPTRTAG="x-eduroam:radius.tls"

DIGCMD=$(command -v dig)
HOSTCMD=$(command -v host)
PRINTCMD=$(command -v printf)

#
#  These validations prevent rogue DNS records from pwning your RADIUS installation.
#
#  See https://github.com/radsecproxy/radsecproxy/security/advisories/GHSA-56gw-9rj9-55rc
#  and https://www.usenix.org/conference/usenixsecurity21/presentation/jeitner
#
#  The contents of these validation routines should NOT be changed without a deep understanding
#  of DNS!
#
validate_host() {
	echo ${@} | tr -d '\n\t\r' | grep -E '^[_0-9a-zA-Z][-._0-9a-zA-Z]*$'
}

validate_port() {
	echo ${@} | tr -d '\n\t\r' | grep -E '^[0-9]+$'
}

dig_it_srv() {
	${DIGCMD} +short srv $SRV_HOST | sort -n -k1 |
	while read line; do
		set $line
		PORT=$(validate_port $3)
		HOST=$(validate_host $4)
		if [ -n "${HOST}" ] && [ -n "${PORT}" ]; then
			$PRINTCMD "\tipaddr = ${HOST%.}\n\tport = ${PORT}\n"
		fi
	done
}

dig_it_naptr() {
	${DIGCMD} +short naptr "${REALM}" | grep $NAPTRTAG | sort -n -k1 |
	while read line; do
		set $line
		TYPE=$3
		HOST=$(validate_host $6)
		if ( [ "$TYPE" = "\"s\"" ] || [ "$TYPE" = "\"S\"" ] ) && [ -n "${HOST}" ]; then
			SRV_HOST=${HOST%.}
			dig_it_srv
		fi
	done
}

host_it_srv() {
	${HOSTCMD} -t srv $SRV_HOST | sort -n -k5 |
	while read line; do
		set $line
		PORT=$(validate_port $7)
		HOST=$(validate_host $8) 
		if [ -n "${HOST}" ] && [ -n "${PORT}" ]; then
			$PRINTCMD "\tipaddr ${HOST%.}:${PORT}\n"
		fi
	done
}

host_it_naptr() {
	${HOSTCMD} -t naptr "${REALM}" | grep $NAPTRTAG | sort -n -k5 |
	while read line; do
		set $line
		TYPE=$7
		HOST=$(validate_host ${10})
		if ( [ "$TYPE" = "\"s\"" ] || [ "$TYPE" = "\"S\"" ] ) && [ -n "${HOST}" ]; then
			SRV_HOST=${HOST%.}
			host_it_srv
		fi
	done
}

REALM=$(validate_host ${1})
if [ -z "${REALM}" ]; then
	echo "realm \"${1}\" failed validation" >&2
	usage
fi

if [ -x "${DIGCMD}" ]; then
	SERVERS=$(dig_it_naptr)

elif [ -x "${HOSTCMD}" ]; then
	SERVERS=$(host_it_naptr)

else
	echo "${0} requires either \"dig\" or \"host\" command." >&2
	exit 1
fi

if [ ! -n "${SERVERS}" ]; then
	echo "No servers found"  >&2
	exit 1
fi

#
#  Just testing - don't do anything else.
#
if [ -z "${RADMIN}" ]; then
	$PRINTCMD "home_server ${REALM} {\n${SERVERS}\n\t\$INCLUDE tls.conf\n}\n"
	exit 0
fi

#
#  Print out the template, and include the site-local tls.conf file.
#
$PRINTCMD "home_server ${REALM} {\n${SERVERS}\n\t\$INCLUDE tls.conf\n}\n" > $RADDB/home_servers/$1

#
#  @todo - use ${prefix} or some such thing to find radmin.
#
/usr/sbin/radmin -e "add home_server file $RADDB/home_servers/$1"
