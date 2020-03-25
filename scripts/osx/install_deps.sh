#!/bin/sh

#
#  Licensed under CC-BY-ND 4.0 - http://creativecommons.org/licenses/by-nd/4.0/
#
#  Copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
#

#
#  Simple wrapper to install all necessary dependencies on OSX.
#
#  The intent here is to get as many modules here building from source on a
#  FreeRADIUS developer's/contributor's local machine.
#  This script is not intended for use by end users of FreeRADIUS.
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
	echo "Homebrew is required for this script to function" 1>&2
	echo "Install homebrew from https://brew.sh" 1>&2
	exit 1
fi

if ! which git > /dev/null; then
    echo "git is required for this script to function" 1>&2
    echo "Install xcode from the app store, or" 1>&2
    echo "> brew install git" 1>&2
    exit 1
fi

if ! git status > /dev/null 2>&1; then
    echo "This script can only be run from a git repository" 1>&2
    echo "> git clone https://github.com/FreeRADIUS/freeradius-server.git" 1>&2
fi

if ! git-lfs env > /dev/null 2>&1; then
    echo "git-lfs is required for this script to function" 1>&2
    echo "> brew install git-lfs" 1>&2
    echo "> git lfs install" 1>&2
    exit 1
fi

#
#  Install proprietary libraries.
#
#  These are stored on GitHub in git-lfs.
#
if ! git lfs fetch > /dev/null; then
    echo "Failed retrieving proprietary dependencies from git-lfs" 1>&2
    exit 1
fi

if ! git lfs pull; then
    echo "Failed updating dependencies from git-lfs" 1>&2
    exit 1
fi

for i in $(dirname $0)/deps/*.tar.gz; do
	f="$(basename $i)"
	b="$(basename $i .tar.gz)"
	d="/usr/local/$b"
	if [ ! -e "$d" ]; then
		echo "Extracting $b to $d"
		sudo -Es mkdir "$d" || exit 1
		sudo -Es tar -xzf $i -C "$d" || exit 1
	else
	    echo "Skipping $b, already installed"
	fi
done

#
#  Install homebrew dependencies last, as they have the least chance of failing,
#  and we don't want to allow a partial install of build dependencies, as the
#  point is to enable the developer to build as many modules as possible.
#
#  If they want the dependencies installed they can damn well fix git-lfs support.
#
for i in $packages; do
    if ! brew list "$i" > /dev/null 2>&1; then
        brew install "$i"
    else
        echo "Skipping $i, already installed"
    fi
done

exit 0
