#!/bin/sh
#	$Id$

#
#  Set this variable to the location of your SSL installation.
#
[ "$SSL" = "" ] && SSL=/usr/local/ssl
export SSL

#
#  Don't touch the following text.
#
[ -d certs ] && rm -rf certs
mkdir certs
cp xpextensions certs/
cd certs

#
# Generate DH stuff...
#
$(SSL)/bin/openssl gendh > dh

#
#  /dev/urandom is not a file, and we can't rely on "test -e" working
#  everywhere.
#
if ls /dev/urandom >/dev/null 2>&1
then
  dd if=/dev/urandom of=random count=2 >/dev/null 2>&1
else
  echo "Please replace this text with 1k of random data" > random
fi

rm -f CA.log
../CA.certs > CA.log 2>&1
if [ "$?" != "0" ]
then
    echo "  Certificate creation failed."
    echo "  Please see the 'CA.log' file for messages,"
    echo "  or read the 'CA.all' script, and run it by hand."
    echo
    echo "  Sorry."
    exit 1
fi
echo "  See the 'certs' directory for the certificates."
echo "  The 'certs' directory should be copied to .../etc/raddb/"
echo "  All passwords have been set to 'whatever'"
rm -f CA.log xpextensions
exit 0
