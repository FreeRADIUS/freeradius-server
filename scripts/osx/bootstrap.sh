#!/bin/sh
#
#  Simple wrapper to install all necessary dependencies on OSX.
#

packages="
asciidoctor
autoconf
cassandra
curl
freetds
gcc
gperftools
hiredis
isc-dhcp
json-c
krb5
libcouchbase
libidn
libmemcached
libpcap
libyubikey
llvm
luajit
make
mruby
mysql-client
openldap
openssl@1.1
pandoc
pcre2
perl
postgresql
python
readline
talloc
unbound
unixodbc
ykclient
"

if ! which brew > /dev/null; then
	echo "Please install homebrew from https://brew.sh"
	exit 1
fi

for i in $packages; do
	brew list $i > /dev/null 2>&1 || brew install $i
done
