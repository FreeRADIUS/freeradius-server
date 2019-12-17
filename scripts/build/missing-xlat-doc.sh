#!/bin/bash
# Script used to verify the xlat funcs vs documentation

# main()

#
#  Which API functions are used to register xlats
#
xlat_api_funcs="xlat_register|xlat_async_register"
src_dir="src/"
doc_xlat="doc/"

#
#  Where our output goes.
#
OUTPUT=$1
shift

if [ -z "$OUTPUT" ]; then
	echo "Usage: $0 /path/output"
	exit 1
fi

#
#  Where the correct output is located
#
CORRECT=$(echo $0 | sed 's/\.sh/.txt/')

rm -f $OUTPUT
mkdir -p $(dirname $OUTPUT)
touch $OUTPUT

#
#  Search through all of the code for references to xlat API
#  registration functions.  Then, pull out the names of the xlats
#  which are registered.
#
grep --include "*.c" -E "($xlat_api_funcs).*\"" -r $src_dir 2>&1 | \
	perl -lpe 's/^.*"(.*)".*$/\1/' | sort | uniq | \

#
#  Search through the documentation for references to the names of the
#  registered xlat functions.
#
while read _d; do
        echo "CHECKING for %{$_d: ... }"
	if ! grep -q "%{$_d:" --include "*.adoc" -r $doc_xlat 2>&1; then
		echo "%{$_d:...}" >> $OUTPUT
	fi
done

#
#  Files should be identical.  If not, panic.
#
if ! diff $OUTPUT $CORRECT 2>/dev/null ; then
        echo "FAILED: $@"
	echo
	echo "ERROR: Some registered xlats are not documented."
	echo "Please compare the following two files:"
	echo "    expected - $CORRECT"
        echo "    found    - $OUTPUT"
	echo
	echo "If the found output is correct, then just copy 'found' to 'expected'".
	echo
	echo "If the xlat is built-in, please document it in"
	echo "    doc/antora/modules/unlang/pages/xlat/builtin.adoc"
	echo
	echo "If the xlat is in a module, please document it in"
	echo "    raddb/mods-available/NAME"
	exit 1
fi

exit 0
