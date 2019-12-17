#!/bin/bash

# mods src/modules/rlm_$mod
ignored_mods="rlm_(test|example|sql)"

# directories to be ignored
ignored_dirs="src/(include|freeradius-devel|modules)"

# ignored config options
ignored_keys="(local_state_dir|sbin_dir)"

# main()
dir_modules="src/modules"

#
# Look up for FR_CONF in src/modules/rlm_${mod} and cross with raddb/mods-available/${mod}
#
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

#
# Look up for FR_CONF in src/*
#
grep -l --include="*.c" -r FR_CONF_ src | egrep -v "${ignored_dirs}" | sort -n | uniq | \
while read fr_conf_file; do
	grep "FR_CONF_" $fr_conf_file | sed '/_DEPRECATED/d; /_SUBSECTION/d; s/^.*{ FR_CONF_.*("//g; s/".*$//g' | \
	sort | uniq | egrep -v "${ignored_keys}" | \
	while read fr_conf; do
		if ! grep -q "${fr_conf}.*=" -r raddb/; then
			echo "WARNING: ${fr_conf_file}: '${fr_conf}' has no reference in raddb/*"
		fi
	done
done | sort -n

exit 0
