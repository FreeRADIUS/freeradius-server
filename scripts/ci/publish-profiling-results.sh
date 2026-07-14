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
#  Usage: publish-profiling-results.sh <url>

set -eu

[ $# -eq 1 ] || { echo "usage: $0 <url>" >&2; exit 2; }
url=$1

#  The OIDC audience is the URL's origin (scheme://host).
host_path=${url#*://}
audience="${url%%://*}://${host_path%%/*}"

[ -d prof-results ] || { echo "no prof-results/ tree; skipping"; exit 0; }

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

#  Tar an explicit file list (not the directory) so empty directories and
#  editor droppings never travel.
file_list="$tmpdir/files"
tarball="$tmpdir/prof-results.tar.gz"
find prof-results -type f ! -name '.DS_Store' | sed 's#^prof-results/##' >"$file_list"
if ! [ -s "$file_list" ]; then
	echo "prof-results/ holds no files; skipping"
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
