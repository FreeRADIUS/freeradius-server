#!/bin/bash
# $1 is the realm to look up
# $2 is the $prefix of FreeRADIUS
# $3 is the optional NAPTR tag to look up
DIRECTORY=$2
TARGET1=`$DIRECTORY/bin/naptr-eduroam.sh $1 $3 | \
	sed s/'^server dynamic_radsec.'/'home_server '/g | \
	sed s/host/'ipaddr = '/g | sed s/':'/'\n\tport = '/g | \
	sed s/'\}'//g`
[[ "$TARGET1" != "" ]] && TARGET="$TARGET1
	proto = tcp
	type = auth
	secret = radsec
	tls {
		certificate_file = $DIRECTORY/etc/raddb/certs/server.pem
		private_key_file = $DIRECTORY/etc/raddb/certs/server.key
		ca_path = $DIRECTORY/etc/raddb/certs/
	}
}"
echo "$TARGET"
if [ "$TARGET" != "" ]; then 
	echo "$TARGET" >$DIRECTORY/etc/raddb/home_servers/$1; 
	$DIRECTORY/sbin/radmin -e "add home_server file $DIRECTORY/etc/raddb/home_servers/$1"
fi
