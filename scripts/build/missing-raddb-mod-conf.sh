#!/bin/bash

# mods src/modules/rlm_$mod
ignored_mods="rlm_(test|example|sql)"

# main()
dir_modules="src/modules"

# Only "rlm_*"
for _mod in $(ls $dir_modules | grep "^rlm_" | grep -vE "${ignored_mods}"); do
	mod_name="${_mod/rlm_/}"
	mod_dir="${dir_modules}/${_mod}"
	mod_conf="raddb/mods-available/${mod_name}"

	[ ! -d "${mod_dir}" ] && continue

	# raddb?
	if ! [ -f "${mod_conf}" ]; then
		echo "WARNING: Module ${mod_dir} has no ${mod_conf}"
		continue
	fi

	# Get all FR_CONF_*
	grep -r FR_CONF_ ${mod_dir} | sed '/_DEPRECATED/d; /_SUBSECTION/d; s/^.*{ FR_CONF_.*("//g; s/".*$//g' | \
		sort | uniq | \
		while read fr_conf; do
			if ! grep -q "${fr_conf}" "${mod_conf}"; then
				echo "WARNING: ${mod_conf} has no reference for: ${fr_conf}"
			fi
		done
done

exit 0
