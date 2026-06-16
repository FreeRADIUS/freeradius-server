#!/bin/sh
#
#  What this does
#  --------------
#  After a profiling CI run finishes, look for a prof-results/ directory and,
#  if it is there, publish it to the long-lived prof-results store so the
#  profiling web UI can show the new run. The store is run by the
#  cinfra-profiling-server container, which the cinfra platform sits in front
#  of.
#
#  The publish is a single request: we tar.gz the whole prof-results/ tree and
#  POST it to the store's ingest endpoint. Everything stateful happens
#  server-side, inside the container: it validates and unpacks the tarball,
#  allocates the store run indexes (renumbering this run's local indexes to
#  follow whatever the store already holds for the same <branch>/<sha>, under
#  a lock so concurrent publishes cannot collide), records the publish in the
#  run-index-map.json ledger, and rebuilds manifest.json for the UI. This
#  script only packs and ships; the cinfra-profiling-server README documents
#  the store side.
#
#  A small routing detail worth knowing: we POST to /profiling/data/_ingest,
#  but Traefik removes the /profiling prefix on the way in, so the container
#  sees /data/_ingest.
#
#  How we authenticate
#  -------------------
#  No shared password. The runner mints a GitHub OIDC token whose audience is
#  the store URL, and the store's access.lua checks the token's signature and
#  the repo it came from. That is the only credential involved. The server
#  also reads the GitHub run id / attempt / number for its ledger from that
#  verified token, so nothing here needs to send them.
#
#  When we stop and fail
#  ---------------------
#  No prof-results/ directory (or no files in it)? Nothing to do, so we exit 0
#  quietly. Otherwise the publish is all-or-nothing: any non-2xx response (or
#  no response) fails this script and the CI leg with it. A failed publish is
#  safe to re-run; the server derives run numbering so that a retry of a
#  half-landed publish overwrites the half-landed files rather than
#  duplicating them.
#
#  Why everything goes through a proxy
#  -----------------------------------
#  The runner cannot reach the store directly (egress is firewalled), so both
#  the token mint and the upload go through the squid proxy. The connect
#  timeout keeps us from hanging when the store is down; it does not limit the
#  transfer itself.
#
#  The upload size cap
#  -------------------
#  The proxy in front of the store caps request bodies, so we check the
#  tarball size before uploading and fail with a clear message instead of an
#  opaque 413. The store's README documents the cap and the options if
#  publishes outgrow it.
#
#  Usage
#  -----
#    publish-profiling-results.sh
#
#  Environment variables
#  ---------------------
#    PROF_RESULTS_URL                 Base URL of the store (required).
#    ACTIONS_ID_TOKEN_REQUEST_TOKEN   } GitHub OIDC request credentials, set by
#    ACTIONS_ID_TOKEN_REQUEST_URL     } the runner when id-token: write is on.
#    PROF_MAX_UPLOAD_MB               Pre-upload tarball size limit in MB
#                                     (default 45, just under the proxy's
#                                     request-body cap).

set -eu

: "${PROF_RESULTS_URL:?store URL required}"

[ -d prof-results ] || { echo "no prof-results/ tree; skipping"; exit 0; }

#
#  Pack the tree. We tar an explicit file list (not the directory) so empty
#  run directories - a test can claim a run index and then write nothing - and
#  editor droppings never travel; the server only ever sees real result files.
#
list=$(mktemp)
tarball=$(mktemp).tar.gz
find prof-results -type f ! -name '.DS_Store' | sed 's#^prof-results/##' >"$list"
if ! [ -s "$list" ]; then
	echo "prof-results/ holds no files; skipping"
	rm -f "$list" "$tarball"
	exit 0
fi
#  COPYFILE_DISABLE stops tar implementations that honour it from adding
#  synthetic ._* metadata members for extended attributes; GNU tar on the CI
#  runner ignores the variable entirely.
COPYFILE_DISABLE=1 tar -czf "$tarball" -C prof-results -T "$list"
rm -f "$list"

#
#  Refuse to ship a tarball the front proxy would 413. The check is
#  client-side only, so a raised proxy limit just needs a bigger
#  PROF_MAX_UPLOAD_MB here.
#
max_mb=${PROF_MAX_UPLOAD_MB:-45}
size=$(wc -c <"$tarball")
size_mb=$(( (size + 1048575) / 1048576 ))
if [ "$size_mb" -gt "$max_mb" ]; then
	echo "ERROR: publish tarball is ${size_mb} MB, over the ${max_mb} MB limit" >&2
	echo "ERROR: the proxy in front of the store caps request bodies; raise that cap" >&2
	echo "ERROR: (and PROF_MAX_UPLOAD_MB), or split the publish per run" >&2
	rm -f "$tarball"
	exit 1
fi

#
#  Mint an OIDC token whose audience is the store URL. The `|| true` is
#  deliberate: it stops set -e from killing us on a hiccup so the check just
#  below can print a friendly message instead of a bare non-zero exit.
#
token=$(curl -sS \
	-H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
	"$ACTIONS_ID_TOKEN_REQUEST_URL&audience=${PROF_RESULTS_URL}" \
	| jq -r '.value') || true
if [ -z "$token" ] || [ "$token" = null ]; then
	echo "ERROR: could not obtain OIDC token" >&2
	rm -f "$tarball"
	exit 1
fi

#
#  Ship it. One POST; the server answers with a JSON summary of what it
#  published (or an { "error": ... } explaining why it refused). No automatic
#  retry: if the server succeeded but the response got lost, a blind retry
#  would append a duplicate set of runs, so leave retrying to a human re-run
#  of the CI leg.
#
echo "publishing $(du -h "$tarball" | cut -f1 | tr -d ' ') prof-results tarball"
resp=$(mktemp)
code=$(curl -sS --connect-timeout 10 -o "$resp" -w '%{http_code}' \
	-X POST -H "Authorization: Bearer $token" \
	--data-binary @"$tarball" \
	"${PROF_RESULTS_URL}/profiling/data/_ingest") || code=000
rm -f "$tarball"

cat "$resp"; echo
case "$code" in
	2??)
		rm -f "$resp"
		exit 0
		;;
	*)
		echo "ERROR: publish failed (HTTP $code)" >&2
		rm -f "$resp"
		exit 1
		;;
esac
