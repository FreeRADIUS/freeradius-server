#!/bin/bash
# $1 is the realm to look up
# $2 is the $prefix of FreeRADIUS
DIRECTORY=$2
TARGET1=`$DIRECTORY/bin/naptr-eduroam.sh $1 | \
	sed s/'^server dynamic_radsec.'/'home_server '/g | \
	sed s/host/'ipaddr = '/g | sed s/':'/'\n\tport = '/g | \
	sed s/'\}'//g`
[[ "$TARGET1" != "" ]] && TARGET="$TARGET1
	proto = tcp
	type = auth
	secret = radsec
	tls {
		certificate_file = $DIRECTORY/raddb/certs/server.pem
		private_key_file = $DIRECTORY/raddb/certs/server.key
		ca_path = $DIRECTORY/raddb/certs/ca/
	}
}"
echo "$TARGET"
if [ "$TARGET" != "" ]; then 
	echo "$TARGET" >$DIRECTORY/etc/raddb/home_servers2/$1; 
	$DIRECTORY/sbin/radmin -e "add home_server file $DIRECTORY/etc/raddb/home_servers/$1"&
fi
