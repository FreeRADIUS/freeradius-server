#!/bin/bash
# Script used to verify the xlat funcs vs documentation

# everything here will be ignored.
ignore_funcs="trigger|test"

# ignore rlm_dict xlat's
ignore_funcs="$ignore_funcs|attr|attr_by_num|attr_by_oid|attr_num|vendor|vendor"

# main()
src_dir="src/"
doc_xlat="doc/"
tmp_file="/tmp/missing-xlat-doc.$$"
ret=0

grep --include "*.c" -E '(xlat_register|xlat_async_register).*"' -r $src_dir 2>&1 | \
	grep -vE "($ignore_funcs)" | perl -lpe 's/^.*"(.*)".*$/\1/' | sort | uniq | \
while read _d; do
	if ! grep -q "%{$_d:" --include "*.adoc" -r $doc_xlat 2>&1; then
		echo "%{$_d:...}" >> $tmp_file
	fi
done

echo "****************************************************************"
echo " WARNING: Ignoring documentation for the xlat's: $ignore_funcs"
echo "****************************************************************"

if [ -s "$tmp_file" ]; then
	echo "****************************************************************"
	echo " ERROR: The below xlat's functions are not documented in $doc_xlat"
	echo "****************************************************************"
	cat $tmp_file
	ret=1
fi

rm -f $tmp_file
exit $ret
