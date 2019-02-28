#!/bin/sh -e

parentdir=`dirname $0`

cd $parentdir
parentdir=`pwd`
m4include="-I$parentdir -I$parentdir/m4 -Im4"

libtoolize -f -c
#aclocal
autoheader
autoconf

mysubdirs="$mysubdirs `find src/modules/ -name configure -print | sed 's%/configure%%'`"
mysubdirs=`echo $mysubdirs`

for F in $mysubdirs
do
	echo "Configuring in $F..."
	(cd $F && grep "^AC_CONFIG_HEADER" configure.ac > /dev/null || exit 0; autoheader $m4include)
	(cd $F && autoconf $m4include)
done
