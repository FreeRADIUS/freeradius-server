#!/bin/sh

#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
#  Copyright 2023 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
#

# Files
version_file=VERSION
commit_file=VERSION_COMMIT
commit_depth_file=VERSION_COMMIT_DEPTH
release_file=RELEASE

# Defaults
version_major=4
version_minor=0
version_incrm=
version_prerelease=
commit=
commit_depth=
is_release=0
in_repo=

#
#  Don't allow git to search in directories above this one, as we may
#  be operating in an extracted version of the source and not a repo.
#
git="git --git-dir=.git"

#
#  Check if we're operating in a repo
#
in_repo=$(${git} rev-parse > /dev/null 2>&1 && echo true || echo false)

usage()
{
	echo "$(basename "$0") [-h|-d] [component [component...]] - Create a FreeRADIUS version string from one or more components"
	echo
	echo "component may be one of:"
	echo "major             Major version component from ${version_file}."
	echo "minor             Minor version component from ${version_file}."
	echo "incrm             Incremental version component from ${version_file}."
	echo "prerelease        Pre-release version component from ${version_file}."
	echo "commit            Short (8 hexit) commit hash."
	echo "commit_depth      How many commit since the last tag."
	echo "is_release        true if the current commit has been tagged as a release, else false."
	echo "*                 Any other string.  Will be echoed directly to stdout."
	echo
	echo "arguments:"
	echo "-h                Print helptext"
	echo "-c                Remove ${commit_file}, ${commit_depth_file} and ${release_file} files."
	echo "-d                Write commit, commit_depth, is_release to ${commit_file}, ${commit_depth_file}, ${release_file} respectively."
}

version_component()
{
	for c in "$@"; do
	case "$c" in
	major)
		out=$(cut -f1 -d~ 2>/dev/null < ${version_file} | cut -f1 -d.)
		if [ -z "${out}" ]; then out="${version_major}"; fi
	;;

	minor)
		out=$(cut -f1 -d~ 2>/dev/null < ${version_file} | cut -f2 -d.)
		if [ -z "${out}" ]; then out="${version_minor}"; fi
	;;

	incrm)
		out=$(cut -f1 -d~ 2>/dev/null < ${version_file} | cut -f3 -d.)
		if [ -z "${out}" ]; then out="${version_incrm}"; fi
	;;

	prerelease)
		out=$(cut -s -f2 -d~ 2>/dev/null < ${version_file})
		if [ -z "${out}" ]; then out="$version_prerelease"; fi
	;;

	commit)
		out=$(\
			cat ${commit_file} 2> /dev/null || \
			(${in_repo} && ${git} rev-parse --short=8 HEAD) || \
			echo "${commit}"\
		)
	;;

	commit_depth)
		out=$(\
			cat ${commit_depth_file} 2> /dev/null || \
			(${in_repo} && ${git} describe --tags --match 'branch_*' --match 'release_*' | cut -s -d '-' -f 2) || \
			echo "${commit_depth}" \
		)
	;;

	# - If $RELEASE is set, that takes precedence
	# - Otherwise if a RELEASE file is present, then release = 1.
	# - If we're in a git repo
	#    - If there's a release_* tag matching the current commit,
	#      and there are no uncommented changes then release = 1, and if not release = 0
	# - else release is 1
	is_release)
		out=$(\
			([ -n "${RELEASE}" ] && echo "${RELEASE}" ) || \
			([ -e "${release_file}" ] && echo 1) || \
			(${in_repo} && ( (${git} describe --match='release_*' --exact-match > /dev/null 2>&1 && ${git} status > /dev/null && echo 1) || echo 0) ) || \
			echo "${is_release}" \
		)
	;;

	*)
		out="$c"
	;;
	esac
	printf '%s' "${out}" | tr -d '\n'
	done
}

#
#  Parse any arguments
#
while getopts "hcd" arg; do
	case $arg in
	h)
		usage
	;;

	c)
		[ ! -e "${commit_file}" ] || rm "${commit_file}"
		[ ! -e "${commit_depth_file}" ] || rm "${commit_depth_file}"
		[ ! -e "${release_file}" ] || rm "${release_file}"
		exit 0
	;;

	d)
		# Intermediary variables to quite shellcheck SC2005 as it doesn't
		# seem to be able to differentiate between functions are other
		# commands.
		commit="$(version_component commit)"
		echo "$commit" > "${commit_file}"
		commit_depth="$(version_component commit_depth)"
		echo "$commit_depth" > "${commit_depth_file}"
		[ "$(version_component is_release)" -eq 1 ] && touch "${release_file}"
		exit 0
	;;

	*)
		exit 64
	esac
done
shift $((OPTIND-1))

version_component "$@"
echo
