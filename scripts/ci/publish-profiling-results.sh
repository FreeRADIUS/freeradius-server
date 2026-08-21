#!/bin/sh
#
#  Tar up the prof-results/ directory (if any) and POST the tarball, with a
#  GitHub OIDC bearer token, to the URL given as the only argument. A missing
#  or empty prof-results/ is a quiet exit 0; any other failure exits non-zero
#  so the CI leg fails with it.
#
#  The runner sets ACTIONS_ID_TOKEN_REQUEST_TOKEN / ACTIONS_ID_TOKEN_REQUEST_URL
#  automatically when the job has "id-token: write"; the script uses them to
#  mint an OIDC token whose audience is the target URL's origin.
#

set -eu

usage()
{
	cat <<EOF
Usage: ${0##*/} <url>

Tar prof-results/ and POST the tarball to <url> with a GitHub OIDC token.
Core dumps are excluded; collect-core-dumps.sh keeps those instead. Run from
the directory holding prof-results/. A missing prof-results/ tree, or one
holding nothing publishable, is a quiet success.

Fails without publishing when any test's valgrind-exit-status is non-zero or
missing, because a run valgrind killed has truncated callgrind output whose
numbers are not comparable with previous runs. Set PROF_PUBLISH_PRUNE_UNCLEAN=1
to prune the unclean tests' directories and publish the clean remainder
instead: the store then receives only comparable data, and a run where every
test is unclean still publishes nothing.

  <url>  Where to POST. Its origin becomes the OIDC audience.
  -h     Show this help.

Needs ACTIONS_ID_TOKEN_REQUEST_TOKEN and ACTIONS_ID_TOKEN_REQUEST_URL, which
the runner sets when the job has "id-token: write".

Example:
  ${0##*/} https://cinfra-ca.inkbridge.io/profiling/data
EOF
}

case ${1:-} in
-h|--help)
	usage
	exit 0
	;;
esac

[ $# -eq 1 ] || { usage >&2; exit 2; }
url=$1

#  The OIDC audience is the URL's origin (scheme://host).
host_path=${url#*://}
audience="${url%%://*}://${host_path%%/*}"

[ -d prof-results ] || { echo "no prof-results/ tree; skipping"; exit 0; }

#  Refuse to publish a run valgrind did not finish cleanly. start_valgrind_-
#  profiling.sh drops a valgrind-exit-status file in each test's results dir; a
#  non-zero status means valgrind was killed, which leaves callgrind output
#  truncated at whatever point it died. Numbers from a truncated run are not
#  comparable with a clean one, and publishing them silently poisons the
#  per-suite history the regression gate compares against. Exits non-zero so
#  the leg goes red rather than passing with nothing uploaded.
#
#  A results dir holding the wrapper's log but no valgrind-exit-status is just
#  as unclean: the wrapper writes valgrind_profiling.log first and the status
#  file only after valgrind exits, so a missing status file means the wrapper
#  was killed mid-run (e.g. the container was torn down around a hung
#  shutdown) and never saw valgrind finish.
unclean=""
for status_file in $(find prof-results -type f -name valgrind-exit-status | sort); do
	read -r status <"$status_file" || status="unreadable"
	case $status in
	0)	continue ;;
	esac
	unclean="${unclean} ${status_file%/valgrind-exit-status}:${status}"
done
for wrapper_log in $(find prof-results -type f -name valgrind_profiling.log | sort); do
	dir=${wrapper_log%/valgrind_profiling.log}
	[ -f "$dir/valgrind-exit-status" ] || unclean="${unclean} ${dir}:missing"
done
#  Exit statuses above 128 are 128 + signal number; name the common ones so
#  the CI log reads as a cause, not a bare number.
explain_status()
{
	case $1 in
	missing)
		echo "no exit status recorded: the profiling wrapper was killed mid-run" ;;
	134)	echo "status 134: SIGABRT, usually a freeradius assert (see the freeradius.log line below)" ;;
	137)	echo "status 137: SIGKILL (out-of-memory killer, or forced container teardown)" ;;
	139)	echo "status 139: SIGSEGV (crash)" ;;
	143)	echo "status 143: SIGTERM (asked to shut down mid-run)" ;;
	*)	if [ "$1" -gt 128 ] 2>/dev/null; then
			echo "status $1: killed by signal $(($1 - 128))"
		else
			echo "valgrind exited with status $1"
		fi ;;
	esac
}

if [ -n "$unclean" ]; then
	if [ "${PROF_PUBLISH_PRUNE_UNCLEAN:-0}" = "1" ]; then
		echo "WARNING: pruning tests where valgrind did not finish cleanly:" >&2
	else
		echo "ERROR: refusing to publish, valgrind did not finish cleanly in:" >&2
	fi
	for entry in $unclean; do
		dir=${entry%:*}
		echo "         ${dir}" >&2
		echo "           $(explain_status "${entry##*:}")" >&2
		#  Valgrind passes the profiled server's exit status through, so the
		#  cause usually lives in freeradius.log (asserts, caught signals),
		#  not valgrind.log. Quote the first such line so the cause is
		#  visible without downloading the artifact. NOTE: valgrind.log's
		#  "brk segment overflow" warning appears in clean runs too (glibc
		#  falls back to mmap); do not treat it as the failure reason.
		diag=$(grep -E -m1 "ASSERT FAILED|CAUGHT SIGNAL|_EXIT\(|PANIC" "$dir/freeradius.log" 2>/dev/null || true)
		if [ -n "$diag" ]; then
			echo "           freeradius.log: ${diag}" >&2
		else
			diag=$(grep -E -m1 "Assertion|FATAL|out of memory|impossible happened|Fatal error" "$dir/valgrind.log" 2>/dev/null || true)
			[ -n "$diag" ] && echo "           valgrind.log: ${diag}" >&2
		fi
	done
	if [ "${PROF_PUBLISH_PRUNE_UNCLEAN:-0}" != "1" ]; then
		echo "ERROR: truncated profiling data is not comparable with previous runs" >&2
		exit 1
	fi
	#  Prune mode: drop each unclean test's directory so only comparable data
	#  travels. An all-unclean run leaves nothing publishable and exits 0 at
	#  the empty-file-list check below, same as an empty tree.
	for entry in $unclean; do
		rm -rf "${entry%:*}"
	done
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

#  Tar an explicit file list (not the directory) so empty directories and
#  editor droppings never travel.
all_list="$tmpdir/all"
core_list="$tmpdir/cores"
file_list="$tmpdir/files"
tarball="$tmpdir/prof-results.tar.gz"
#  Paths are kept with a leading "/" while filtering, so a basename is always
#  preceded by "/" and the pattern below needs no "(^|/)" alternation, which
#  not every grep implementation accepts. The slash comes off again when the
#  tar file list is written.
find prof-results -type f ! -name '.DS_Store' | sed 's#^prof-results##' | sort >"$all_list"

#  Drop core dumps. A crash under valgrind dumps the whole address space, so
#  one core is ~1.5G; two of them turned a 6M publish into 35M of mostly-zero
#  pages and pushed the store's synchronous ingest past the 60s gateway read
#  timeout, failing the CI leg on a publish that had in fact landed. Cores are
#  collected by collect-core-dumps.sh and uploaded as a workflow artifact, so
#  nothing is lost by keeping them out of the store, which only wants
#  profiling data. core_dump_re is shared with that script.
. "$(dirname "$0")/core-dump-names.inc"
grep -E "$core_dump_re" "$all_list" >"$core_list" || true
grep -Ev "$core_dump_re" "$all_list" | sed 's#^/##' >"$file_list" || true

#  Never drop files silently: an unexplained gap in a run's tree is worse than
#  a noisy publish log.
if [ -s "$core_list" ]; then
	echo "excluding $(wc -l <"$core_list" | tr -d ' ') core dump(s) from the store publish:"
	while IFS= read -r core; do
		echo "  $(du -h "prof-results$core" | cut -f1 | tr -d ' ')	${core#/}"
	done <"$core_list"
fi

if ! [ -s "$file_list" ]; then
	echo "prof-results/ holds no publishable files; skipping"
	exit 0
fi
tar -czf "$tarball" -C prof-results -T "$file_list"

#  The || true keeps set -e out of the way so the check below can print a
#  clear message on a failed mint.
token=$(curl -sS \
	-H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
	"$ACTIONS_ID_TOKEN_REQUEST_URL&audience=${audience}" \
	| jq -r '.value') || true
if [ -z "$token" ] || [ "$token" = null ]; then
	echo "ERROR: could not obtain OIDC token" >&2
	exit 1
fi

#  The publish carries the commit subject and the branch name as extra HTTP
#  headers. The store's run picker displays both, and the branch name is what
#  links the run back to GitHub: the store replaces "/" with "_" in its
#  directory names, so the header is the only place the real branch name
#  survives. If either value cannot be determined the script is not running
#  in its normal CI context, and the publish stops and errors out.
#  The values travel base64-encoded.
subject=$(git log -1 --format=%s 2>/dev/null | head -c 200)
if [ -z "$subject" ]; then
	echo "ERROR: cannot read the commit subject (git log failed)" >&2
	exit 1
fi
if [ -z "${GITHUB_REF_NAME}" ]; then
	echo "ERROR: GITHUB_REF_NAME is not set; cannot record the branch" >&2
	exit 1
fi
subject_b64=$(printf '%s' "$subject" | base64 | tr -d '\n')
branch_b64=$(printf '%s' "$GITHUB_REF_NAME" | head -c 200 | base64 | tr -d '\n')

echo "publishing $(du -h "$tarball" | cut -f1 | tr -d ' ') prof-results tarball"
resp="$tmpdir/response"
code=$(curl -sS --connect-timeout 10 -o "$resp" -w '%{http_code}' \
	-X POST -H "Authorization: Bearer $token" \
	-H "X-Prof-Commit-Subject-B64: $subject_b64" \
	-H "X-Prof-Branch-Ref-B64: $branch_b64" \
	--data-binary @"$tarball" \
	"$url") || code=000

case "$code" in
	2??) exit 0 ;;
	*)
		echo "ERROR: publish failed (HTTP $code)" >&2
		[ -s "$resp" ] && { cat "$resp" >&2; echo >&2; }
		exit 1
		;;
esac
