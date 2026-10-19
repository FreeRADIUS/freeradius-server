#!/bin/sh
#
#  Print the build dependencies that one family of CI images installs, as
#  declared at one git revision.
#
#  The CI images install the build dependencies from the packaging files,
#  and read nothing else from the packaging files.  Most changes under
#  `redhat/` or `debian/` change packaging only, for example a `%files` line,
#  and leave the images as the images were.  `common_vars.yml` therefore runs
#  this script at this ref and at the base revision, and counts a packaging
#  change as an image change only when the two outputs differ.
#
#  The output holds more than the dependencies themselves.  The output also
#  holds every conditional and macro definition that can change a
#  dependency, so a change to any of those counts as an image change too.
#
#  Usage: images-build-deps.sh <rpm|deb> <revision>
#
#    rpm  Everything before `%prep` in `redhat/freeradius.spec` that declares
#         a `BuildRequires`, a conditional, or a macro.  `%prep` follows the
#         preambles of the main package and of every subpackage, and only a
#         preamble can declare a `BuildRequires`.
#    deb  The `Build-Depends` and `Build-Conflicts` fields of
#         `debian/control.in`, and the lines of `debian/rules` that set
#         `CONTROL_BUILDDEPS` or open or close a conditional.
#         `debian/rules` substitutes `CONTROL_BUILDDEPS` for `@BUILDDEPS@`
#         when the rules generate `debian/control`.
#
#  The script exits non-zero when a file is absent at the revision.
#

usage() {
	echo "Usage: $0 <rpm|deb> <revision>" 1>&2
	exit 2
}

[ "$#" -eq 2 ] || usage

family="$1"
revision="$2"

case "$family" in
rpm)
	spec=$(git show "$revision:redhat/freeradius.spec") || exit 1
	printf '%s\n' "$spec" \
		| sed -n '1,/^%prep/p' \
		| grep -E 'BuildRequires|^%(if|elif|else|endif|bcond|global|define)'
	;;

deb)
	control=$(git show "$revision:debian/control.in") || exit 1
	rules=$(git show "$revision:debian/rules") || exit 1

	#  A field continues on every following line that starts with a space
	#  or a tab.
	printf '%s\n' "$control" \
		| awk '/^Build-(Depends|Conflicts)/ { in_field = 1; print; next }
		       in_field && /^[ \t]/ { print; next }
		       { in_field = 0 }'
	printf '%s\n' "$rules" \
		| grep -E 'BUILDDEPS|^[ \t]*(ifeq|ifneq|ifdef|ifndef|else|endif)'
	;;

*)
	usage
	;;
esac

exit 0
