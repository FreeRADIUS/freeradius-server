#!/bin/sh
#
#  Publish a run's prof-results/ tree to the durable prof-results store
#  (a WebDAV endpoint fronted by the cinfra platform). Every file under
#  prof-results/ is uploaded into the store's volume, then the store's
#  manifest is refreshed so the browser UI sees the new run. The store
#  image is static; this only writes files, never rebuilds it. The
#  /profiling prefix is stripped in front of the container, so a file
#  lands at /data/<rel>.
#
#  Auth is a GitHub OIDC token scoped to the store URL (the token's
#  audience), which the store's access.lua verifies (signature + repo),
#  so there is no shared upload secret.
#
#  A missing prof-results/ tree is a clean skip. Once a tree exists, every
#  file and the manifest refresh must succeed, or this script exits
#  non-zero and fails the CI leg.
#
#  --noproxy '*' on the store curls bypasses the squid proxy: the store
#  resolves and is reachable directly, and going direct avoids squid's
#  request-body cap on the multi-MB callgrind.out files. The token mint
#  keeps the proxy, since the GitHub token endpoint is public.
#
#  Usage:
#    publish-profiling-results.sh
#
#  Env:
#    PROF_RESULTS_URL                 Base URL of the store (required).
#    ACTIONS_ID_TOKEN_REQUEST_TOKEN   } GitHub OIDC request credentials,
#    ACTIONS_ID_TOKEN_REQUEST_URL     } set by the runner under id-token: write.

set -eu

: "${PROF_RESULTS_URL:?store URL required}"

[ -d prof-results ] || { echo "no prof-results/ tree; skipping"; exit 0; }

#
#  Mint an OIDC token with the store URL as its audience. `|| true` keeps
#  set -e from killing the script on a transient mint failure, so the
#  explicit check below prints a clear message instead.
#
token=$(curl -sS \
	-H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
	"$ACTIONS_ID_TOKEN_REQUEST_URL&audience=${PROF_RESULTS_URL}" \
	| jq -r '.value') || true
if [ -z "$token" ] || [ "$token" = null ]; then
	echo "ERROR: could not obtain OIDC token" >&2
	exit 1
fi

#  PUT one file ($1) to its path under the store ($2).
upload() {
	curl -fsS --noproxy '*' -H "Authorization: Bearer $token" \
		-T "$1" "${PROF_RESULTS_URL}/profiling/$2"
}

#
#  Upload every file, recording any failure but attempting all of them, so
#  one run surfaces every problem rather than just the first. The file list
#  goes through a temp file (not a `find | while` pipe) so the loop runs in
#  this shell and `fail` survives it.
#
fail=0
list=$(mktemp)
find prof-results -type f ! -name '.DS_Store' >"$list"
while IFS= read -r f; do
	rel="${f#prof-results/}"   # <branch>/<sha>/<run>/<suite>/<test>/...
	upload "$f" "$rel" || { echo "ERROR: failed to upload $rel" >&2; fail=1; }
done <"$list"
rm -f "$list"

#  Refresh the manifest so the UI's read path stays in sync with the tree.
curl -fsS --noproxy '*' -X POST -H "Authorization: Bearer $token" \
	"${PROF_RESULTS_URL}/profiling/_manifest" \
	|| { echo "ERROR: manifest regenerate failed" >&2; fail=1; }

exit "$fail"
