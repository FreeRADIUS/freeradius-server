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

echo "publishing $(du -h "$tarball" | cut -f1 | tr -d ' ') prof-results tarball"
resp="$tmpdir/response"
code=$(curl -sS --connect-timeout 10 -o "$resp" -w '%{http_code}' \
	-X POST -H "Authorization: Bearer $token" \
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
