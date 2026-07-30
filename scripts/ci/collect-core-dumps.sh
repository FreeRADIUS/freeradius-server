#!/bin/sh
#
#  Stage any core dumps found under the given roots into one directory, so a
#  workflow can upload them as an artifact.
#
#  Most of our test suites run with "allow_core_dumps = yes", so a crash can
#  leave a core behind. A core is the only record of a crash that the logs
#  cannot reconstruct, and nothing in CI collected them before, so they were
#  discarded with the runner. Collection runs regardless of whether the suite
#  passed: FreeRADIUS crashing during shutdown does not necessarily fail the
#  suite that provoked the crash (multi-server profiling did exactly that on
#  2026-07-25, reporting success while dumping two 1.5G cores).
#
#  Whether a core is written at all still depends on the ambient RLIMIT_CORE
#  and kernel.core_pattern, which CI does not currently set;
#  "allow_core_dumps = yes" only restores the limit FreeRADIUS inherited
#  (fr_set_dumpable() in src/lib/util/debug.c), it does not raise it. So this
#  script collects what happens to be produced rather than guaranteeing a core
#  exists.
#
#  Never fails: a CI leg's result is decided by its tests, not by whether core
#  collection found anything. Always reports what it staged, so an empty result
#  reads as genuinely empty rather than as a step that quietly did nothing.
#

set -u

self_dir=$(dirname "$0")
outdir=ci-core-dumps
move=no

usage()
{
	cat <<EOF
Usage: ${0##*/} [-m] [-o <outdir>] [root ...]

Stage core dumps found under each <root> into <outdir>, preserving their path
below the root so the suite that crashed stays identifiable. Always exits 0.

  -o <outdir>  Where to stage cores. Default "ci-core-dumps".
  -m           Move cores rather than copying them. Use when a root is itself
               uploaded or published, so a core lands in one place only.
  -h           Show this help.
  root ...     Directories to search. Default the current directory.

Examples:
  ${0##*/}                  # search the working tree
  ${0##*/} . /cores         # also search /cores, as macOS uses
  ${0##*/} -m prof-results  # empty cores out of a tree due to be uploaded
EOF
}

while [ $# -gt 0 ]; do
	case $1 in
	-o)
		[ $# -ge 2 ] || { echo "${0##*/}: -o needs a directory" >&2; exit 2; }
		outdir=$2
		shift 2
		;;
	-m)
		move=yes
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	--)
		shift
		break
		;;
	-*)
		echo "${0##*/}: unknown option $1" >&2
		usage >&2
		exit 2
		;;
	*)
		break
		;;
	esac
done

#  Default to the working tree. Tests run with their cwd inside the checkout,
#  and a relative kernel.core_pattern writes the core next to the crashing
#  process, so the checkout is where a core normally lands.
[ $# -gt 0 ] || set -- .

. "$self_dir/core-dump-names.inc"

found=0
staged=0

for root in "$@"; do
	[ -d "$root" ] || continue

	#  A core can be big enough that a second copy matters on a runner disk,
	#  so link it into place where the filesystem allows and only copy as a
	#  fallback.
	for core in $(find "$root" -type f 2>/dev/null | grep -E "$core_dump_re" | sort); do
		found=$((found + 1))

		#  Guard against a stray text file called "core": upload only what
		#  really is a dump. Without file(1) the name is all we have, so
		#  accept the candidate rather than discard possible evidence.
		if command -v file >/dev/null 2>&1; then
			case $(file -b "$core" 2>/dev/null) in
			*core*) ;;
			*)
				echo "skipping $core (not a core dump)"
				continue
				;;
			esac
		fi

		#  Keep the path below the root, so which suite crashed stays
		#  readable in the artifact.
		rel=$(printf '%s\n' "$core" | sed -e 's#^\./##' -e 's#^/##')
		dest=$outdir/$rel
		mkdir -p "$(dirname "$dest")" || continue

		if [ "$move" = yes ]; then
			mv "$core" "$dest" || continue
		else
			ln "$core" "$dest" 2>/dev/null || cp "$core" "$dest" || continue
		fi

		staged=$((staged + 1))
		echo "staged $(du -h "$dest" | cut -f1 | tr -d ' ')	$rel"
	done
done

if [ "$staged" -gt 0 ]; then
	echo "collected $staged core dump(s) into $outdir ($(du -sh "$outdir" | cut -f1 | tr -d ' ') total)"
else
	echo "no core dumps found under: $*"
fi

if [ "$found" -ne "$staged" ]; then
	echo "note: $((found - staged)) candidate(s) were skipped, see above"
fi

exit 0
