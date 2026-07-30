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

Fails without publishing when any test's valgrind-exit-status is non-zero,
because a run valgrind killed has truncated callgrind output whose numbers are
not comparable with previous runs.

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
unclean=""
for status_file in $(find prof-results -type f -name valgrind-exit-status | sort); do
	read -r status <"$status_file" || status="unreadable"
	case $status in
	0)	continue ;;
	esac
	unclean="${unclean} ${status_file%/valgrind-exit-status}:${status}"
done
if [ -n "$unclean" ]; then
	echo "ERROR: refusing to publish, valgrind exited uncleanly in:" >&2
	for entry in $unclean; do
		echo "         ${entry%:*} (status ${entry##*:})" >&2
	done
	echo "ERROR: truncated profiling data is not comparable with previous runs" >&2
	exit 1
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

#  The commit subject and the real branch ref ride along for the store's run
#  picker (display + GitHub links; the store path converts / to _ in branch
#  names, so the original ref is otherwise lost). base64, because HTTP
#  headers are ASCII and neither value is guaranteed to be.
subject_b64=$(git log -1 --format=%s 2>/dev/null | head -c 200 | base64 | tr -d '\n')
branch_b64=$(printf '%s' "${GITHUB_REF_NAME:-}" | head -c 200 | base64 | tr -d '\n')

echo "publishing $(du -h "$tarball" | cut -f1 | tr -d ' ') prof-results tarball"
resp="$tmpdir/response"
code=$(curl -sS --connect-timeout 10 -o "$resp" -w '%{http_code}' \
	-X POST -H "Authorization: Bearer $token" \
	${subject_b64:+-H "X-Prof-Commit-Subject-B64: $subject_b64"} \
	${branch_b64:+-H "X-Prof-Branch-Ref-B64: $branch_b64"} \
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
