#!/bin/sh
#
#  Publish a run's prof-results/ tree to the durable prof-results store
#  (a WebDAV endpoint fronted by the cinfra platform). Every file under
#  prof-results/ is uploaded into the store's volume, then the store's
#  manifest is refreshed so the browser UI sees the new run. The store
#  image is static; this only writes files, never rebuilds it. Uploads go
#  under /profiling/data/; Traefik strips the /profiling prefix and the store
#  serves its /data/ location from the volume, so a file lands at /data/<rel>.
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
#  Re-running the workflow on the same sha must not clobber the previous
#  attempt, and the store should read as a clean, gapless run sequence per
#  <branch>/<sha> starting at 1. Local run indexes can have gaps: a test that
#  claimed an index but produced no files leaves an empty dir, so the indexes
#  that actually carry results may be 3, 4, ... rather than 1, 2, ... We do not
#  copy them verbatim. Instead the run indexes that carry files are ranked
#  ascending and renumbered to consecutive store indexes starting at offset+1,
#  where offset is the highest run already in the store for this <branch>/<sha>.
#  So a first publish lands 1..K and a re-run appends (offset+1)..(offset+K). The
#  store manifest is the source of truth for the offset; a sha with nothing there
#  (or no manifest yet) gives offset 0, so the first publish starts at 1.
#
#  Usage:
#    publish-profiling-results.sh
#
#  Env:
#    PROF_RESULTS_URL                 Base URL of the store (required).
#    ACTIONS_ID_TOKEN_REQUEST_TOKEN   } GitHub OIDC request credentials,
#    ACTIONS_ID_TOKEN_REQUEST_URL     } set by the runner under id-token: write.
#    GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, GITHUB_RUN_NUMBER, GITHUB_REPOSITORY
#                                     Recorded in the run-index ledger (see the
#                                     ledger note below); absent outside Actions,
#                                     in which case they are recorded as null.

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
		-T "$1" "${PROF_RESULTS_URL}/profiling/data/$2"
}

#
#  Compute the per-<branch>/<sha> run-index offset (see the header note). The
#  store manifest lists every file as <branch>/<sha>/<run>/<suite>/<test>/<file>;
#  fetch it once (public GET, no auth) and, for each <branch>/<sha> prefix in
#  THIS run's tree, record the highest <run> already present. The prefix match
#  carries a trailing "/", so archived trees (<branch>/archive-.../<sha>/...)
#  and a sha that is a prefix of another never count. An absent/empty manifest
#  yields no lines, so every offset is 0 and paths are left as 1..N.
#
#  Deriving the offset from the manifest (the actual files) rather than a
#  separate counter means manual housekeeping - deleting or archiving trees -
#  is reflected automatically. The manifest is read BEFORE any upload, so this
#  run's own files never inflate their own offset. Single-publisher-per-sha is
#  assumed: two runs publishing for the same sha at once could read the same max
#  and collide (deferred).
#
#  The offset is only safe if we can actually read the manifest. A failed read
#  must NOT silently fall back to offset 0 - that would land this run's 1..N on
#  top of an earlier attempt's 1..N and overwrite it. So we inspect the HTTP
#  status: 200 uses the manifest; 404 means the store has no manifest yet (a
#  genuine first publish, offset 0 is correct); anything else (connect failure,
#  5xx, non-JSON body) aborts the publish rather than risk clobbering prior runs.
#
existing=$(mktemp)
body=$(mktemp)
code=$(curl -sS --connect-timeout 10 -o "$body" -w '%{http_code}' \
	"${PROF_RESULTS_URL}/profiling/data/manifest.json") || code=000
case "$code" in
	200)
		jq -r '.files[]?' <"$body" >"$existing" 2>/dev/null || {
			echo "ERROR: store manifest is not valid JSON; refusing to publish (would risk overwriting prior runs)" >&2
			rm -f "$existing" "$body"; exit 1
		}
		;;
	404)
		: ;;   # no manifest yet: genuine first publish, offset 0 is correct
	*)
		echo "ERROR: could not read store manifest (HTTP $code); refusing to publish to avoid reusing run indexes" >&2
		rm -f "$existing" "$body"; exit 1
		;;
esac
rm -f "$body"

offsets=$(mktemp)
find prof-results -type f ! -name '.DS_Store' \
	| sed 's#^prof-results/##' \
	| awk -F/ 'NF>=3 { print $1"/"$2 }' | sort -u \
	| while IFS= read -r pfx; do
		max=$(awk -F/ -v p="$pfx/" '
			substr($0, 1, length(p)) == p && $3 ~ /^[0-9]+$/ && $3 + 0 > m { m = $3 + 0 }
			END { print m + 0 }' "$existing")
		printf '%s\t%s\n' "$pfx" "$max" >>"$offsets"
	done

#
#  Build the run-index remap. For each <branch>/<sha>, take the local run
#  indexes that actually carry files - a test that claimed an index but wrote
#  nothing leaves an empty dir, which `find -type f` never reports, so it drops
#  out here and is neither uploaded nor given a store slot - rank them ascending,
#  and map the k-th to store index offset+k. This compacts gaps away so the store
#  reads a clean 1..K on a first publish and (offset+1)..(offset+K) on a re-run.
#  Keyed by <branch>/<sha>/<run>; the sort is by <branch>/<sha> then numeric run
#  so the rank order is stable.
#
tab=$(printf '\t')
remap=$(mktemp)
find prof-results -type f ! -name '.DS_Store' \
	| sed 's#^prof-results/##' \
	| awk -F/ 'NF>=4 && $3 ~ /^[0-9]+$/ { print $1"/"$2"\t"$3 }' \
	| sort -t"$tab" -k1,1 -k2,2n -u \
	| awk -F'\t' -v offfile="$offsets" '
		BEGIN { while ((getline l < offfile) > 0) { split(l, a, "\t"); off[a[1]] = a[2] } }
		{ if ($1 != prev) { rank = 0; prev = $1 } rank++; printf "%s/%s\t%d\n", $1, $2, off[$1] + rank }
	' >"$remap"

#
#  Ledger rows for the run-index map (see the ledger note further down). One row
#  per file-bearing run: <branch> <sha> <local_run> <store_run> <suite> <test>,
#  joining the suite/test from the tree to the store index from the remap. Built
#  here while $remap is still around; consumed after the uploads succeed.
#
ledgerrows=$(mktemp)
find prof-results -type f ! -name '.DS_Store' | sed 's#^prof-results/##' \
	| awk -F/ 'NF>=5 && $3 ~ /^[0-9]+$/ { print $1"\t"$2"\t"$3"\t"$4"\t"$5 }' \
	| sort -u \
	| awk -F'\t' -v rf="$remap" '
		BEGIN { while ((getline l < rf) > 0) { split(l, a, "\t"); store[a[1]] = a[2] } }
		{ k = $1"/"$2"/"$3; if (k in store) print $1"\t"$2"\t"$3"\t"store[k]"\t"$4"\t"$5 }
	' >"$ledgerrows"

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
	dest="$rel"
	#  Remap the <run> (3rd) segment to its compacted store index (see header).
	#  All files under one local run share the same remapped index, so callgrind
	#  output and logs stay co-located. A non-numeric or unmapped run is left as is.
	branch="${rel%%/*}"; r1="${rel#*/}"
	sha="${r1%%/*}";     r2="${r1#*/}"
	run="${r2%%/*}";     rest="${r2#*/}"
	case "$r2" in
		*/*)   # has at least <run>/<rest>, so there is a run segment to remap
			case "$run" in
				''|*[!0-9]*) : ;;   # non-numeric run: leave dest unchanged
				*)
					dr=$(awk -F'\t' -v k="$branch/$sha/$run" '$1 == k { print $2; exit }' "$remap")
					[ -n "$dr" ] && dest="$branch/$sha/$dr/$rest"
					;;
			esac
			;;
	esac
	upload "$f" "$dest" && continue
	echo "ERROR: failed to upload $dest" >&2
	fail=$((fail + 1))
	if [ "$fail" -ge "$MAX_FAILURES" ]; then
		echo "ERROR: $fail upload failures; giving up (store unreachable?)" >&2
		break
	fi
done <"$list"
rm -f "$list" "$existing" "$offsets" "$remap"

#  A failed upload means an incomplete tree, so skip the manifest refresh
#  (which would advertise runs whose files are missing) and fail the leg.
[ "$fail" -eq 0 ] || { rm -f "$ledgerrows"; exit 1; }

#
#  Append this publish to the run-index ledger (run-index-map.json at the store
#  root, a sibling of manifest.json). It maps each GitHub workflow-run publish
#  (run id + attempt + sha) to the local->store run-index remap it produced, so
#  the compaction is auditable later. The server cannot build this (the on-disk
#  tree carries no GitHub context), so we read the current ledger, merge this
#  publish in, and PUT it back. As with the offset read, a failed ledger read
#  aborts rather than overwrite the history; the manifest is left un-refreshed,
#  so a retry re-derives the same offset/remap and re-publishes idempotently.
#
now=$(date +%s)

#  This publish's entries, grouped by <branch>/<sha> (CI has exactly one sha).
#  store_offset is recovered as min(store_run_index) - 1. Empty/non-result runs
#  never reach $ledgerrows, so they are absent from index_map by construction.
newentries=$(jq -R 'select(length > 0) | split("\t")
		| { branch: .[0], sha: .[1],
		    github_run_index: (.[2] | tonumber), store_run_index: (.[3] | tonumber),
		    suite: .[4], test: .[5] }' "$ledgerrows" \
	| jq -s \
		--argjson now "$now" \
		--arg rid  "${GITHUB_RUN_ID:-}" \
		--arg att  "${GITHUB_RUN_ATTEMPT:-}" \
		--arg num  "${GITHUB_RUN_NUMBER:-}" \
		--arg repo "${GITHUB_REPOSITORY:-}" \
		'group_by([.branch, .sha]) | map({
			github_run_id:      (try ($rid | tonumber) catch null),
			github_run_attempt: (try ($att | tonumber) catch null),
			github_run_number:  (try ($num | tonumber) catch null),
			github_repository:  (if $repo == "" then null else $repo end),
			branch:             .[0].branch,
			sha:                .[0].sha,
			published_epoch:    $now,
			store_offset:       ((map(.store_run_index) | min) - 1),
			index_map:          (map({ github_run_index, store_run_index, suite, test })
			                     | sort_by(.store_run_index))
		})')

#  Read the current ledger: 200 merge, 404 start fresh, anything else abort.
lbody=$(mktemp)
lcode=$(curl -sS --connect-timeout 10 -o "$lbody" -w '%{http_code}' \
	"${PROF_RESULTS_URL}/profiling/data/run-index-map.json") || lcode=000
case "$lcode" in
	200)
		base=$(jq '.' "$lbody") || {
			echo "ERROR: store run-index-map.json is not valid JSON; refusing to update the ledger" >&2
			rm -f "$ledgerrows" "$lbody"; exit 1
		}
		;;
	404)
		base='{"schema":1,"publishes":[]}'
		;;
	*)
		echo "ERROR: could not read store run-index-map.json (HTTP $lcode); refusing to update the ledger" >&2
		rm -f "$ledgerrows" "$lbody"; exit 1
		;;
esac
rm -f "$lbody"

#  Merge: drop any prior entry for this same (run id, attempt, branch, sha) so a
#  retry replaces rather than duplicates, then append this publish's entries and
#  stamp the top-level generated_epoch.
merged=$(mktemp)
printf '%s' "$base" | jq \
	--argjson now "$now" \
	--argjson new "$newentries" \
	'.schema = (.schema // 1)
	 | .generated_epoch = $now
	 | .publishes = ([ .publishes[]? | select(. as $e |
	       ($new | any(.github_run_id      == $e.github_run_id
	               and .github_run_attempt == $e.github_run_attempt
	               and .branch             == $e.branch
	               and .sha                == $e.sha)) | not) ] + $new)' >"$merged" || {
	echo "ERROR: failed to build updated run-index-map.json" >&2
	rm -f "$ledgerrows" "$merged"; exit 1
}

upload "$merged" "run-index-map.json" || {
	echo "ERROR: failed to upload run-index-map.json" >&2
	rm -f "$ledgerrows" "$merged"; exit 1
}
rm -f "$ledgerrows" "$merged"

#  Refresh the manifest so the UI's read path stays in sync with the tree.
curl -fsS --connect-timeout 10 -X POST -H "Authorization: Bearer $token" \
	"${PROF_RESULTS_URL}/profiling/data/_manifest" \
	|| { echo "ERROR: manifest regenerate failed" >&2; exit 1; }

exit 0
