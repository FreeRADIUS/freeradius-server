#!/bin/sh

#
#  Print out "ALIAS NAME OID", which lets us import the v3 names into v4.
#

RADATTR=$(echo $0 | sed 's,dict_alias.sh,../../build/make/jlibtool --quiet --mode=execute ./build/bin/radattr,')
DICTDIR=$(echo $0 | sed 's,dict_alias.sh,../../share,')

#
#  Print out the attributes,
#  sorted by vendor,
#  split off the comment showing the vendor,
#  reformat so that the name is in a 40-character field
#
#  The output is ordered by vendor, which makes it easy to split them manually.
#
#  The output is also ordered by name, instead of by OID.  Which is
#  fine, as ordering it by OID is hard.  Both for "radattr", and for
#  simple shell scripts.
#
$RADATTR -A -D $DICTDIR | sort -n -k5 | sed 's/ #.*//' | awk '{printf "%s\t%-40s\t%s\n", $1, $2, $3 }'
