#!/bin/bash
# Script used to verify the xlat funcs vs documentation

# main()
xlat_api_funcs="xlat_register|xlat_async_register"
src_dir="src/"
doc_xlat="doc/"

grep --include "*.c" -E "($xlat_api_funcs).*\"" -r $src_dir 2>&1 | \
	perl -lpe 's/^.*"(.*)".*$/\1/' | sort | uniq | \
while read _d; do
	if ! grep -q "%{$_d:" --include "*.adoc" -r $doc_xlat 2>&1; then
		echo "%{$_d:...}"
	fi
done
