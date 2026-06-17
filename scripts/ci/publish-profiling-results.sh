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
#  The store is reachable from the runner only through the squid proxy
#  (direct egress is firewalled), so the uploads go through the proxy, the
#  same path as the token mint. A short connect timeout plus a bail-out
#  after MAX_FAILURES keeps an unreachable store from hanging the step on
#  every one of the run's files.
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

#  Give up after this many failed uploads
MAX_FAILURES=3

#  PUT one file ($1) to its path under the store ($2). The connect timeout
#  caps the wait on an unreachable store; it bounds only the connection,
#  not the transfer, so a slow upload of a large file still completes.
upload() {
	curl -fsS --connect-timeout 10 -H "Authorization: Bearer $token" \
		-T "$1" "${PROF_RESULTS_URL}/profiling/$2"
}

#
#  Upload every file, but stop after MAX_FAILURES. The file list goes
#  through a temp file (not a `find | while` pipe) so the loop runs in this
#  shell and the failure count survives it.
#
fail=0
list=$(mktemp)
find prof-results -type f ! -name '.DS_Store' >"$list"
while IFS= read -r f; do
	rel="${f#prof-results/}"   # <branch>/<sha>/<run>/<suite>/<test>/...
	upload "$f" "$rel" && continue
	echo "ERROR: failed to upload $rel" >&2
	fail=$((fail + 1))
	if [ "$fail" -ge "$MAX_FAILURES" ]; then
		echo "ERROR: $fail upload failures; giving up (store unreachable?)" >&2
		break
	fi
done <"$list"
rm -f "$list"

#  A failed upload means an incomplete tree, so skip the manifest refresh
#  (which would advertise runs whose files are missing) and fail the leg.
[ "$fail" -eq 0 ] || exit 1

#  Refresh the manifest so the UI's read path stays in sync with the tree.
curl -fsS --connect-timeout 10 -X POST -H "Authorization: Bearer $token" \
	"${PROF_RESULTS_URL}/profiling/_manifest" \
	|| { echo "ERROR: manifest regenerate failed" >&2; exit 1; }

exit 0
