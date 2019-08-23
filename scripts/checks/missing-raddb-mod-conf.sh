#!/bin/bash

# mods src/modules/rlm_$mod
ignored_mods="rlm_(test|example|sql)"

# main()
dir_modules="src/modules"
mod_cache="/tmp/missing-raddb-cache-$$"

# Only "rlm_*"
for _mod in $(ls $dir_modules | grep "^rlm_" | grep -vE "${ignored_mods}"); do
	mod_name="${_mod/rlm_/}"
	mod_dir="${dir_modules}/${_mod}"
	mod_conf="raddb/mods-available/${mod_name}"

	[ ! -d "${mod_dir}" ] && continue

	# raddb?
	if ! [ -f "${mod_conf}" ]; then
		echo "WARNING: No references of ${mod_dir} in ${mod_conf}"
		continue
	fi

	# Get all FR_CONF_*
	grep "^[^ ]{[ ]FR_CONF_.*(" -r ${mod_dir} | sed '/_DEPRECATED/d; s/^.*{ FR_CONF_.*("//g; s/".*$//g' | \
		sort | uniq | \
		while read fr_conf; do
			if ! grep -q "${fr_conf}" "${mod_conf}"; then
				echo "${mod_conf}:${fr_conf}" >> "${mod_cache}"
			fi
		done
done

if [ -s "${mod_cache}" ]; then
	cat "${mod_cache}" | awk -F ':' '
	{
		mods[$1] = mods[$1]" "$2
	}
	END {
		for (m in mods) {
			printf("WARNING: The %s has no reference for:\n", m)
			split(mods[m], keys, " ")
			for (k in keys) printf("\t%s\n", keys[k])
		}
	}'
fi

rm -f $mod_cache
exit 0
