#!/bin/sh
#
#  Flag the latest profiling results: on a regression, post (or update) a short
#  commit comment pointing at the latest-vs-previous summary hosted by the
#  cinfra-profiling-server container. Advisory only: a commenting failure warns
#  but never fails the build, so this is safe to run continue-on-error after
#  the cest-analyzer gate step.
#
#  The comment is deliberately a few words plus a link: the summary itself
#  lives on the profiling server, not in CI. This workflow runs on push, so
#  there is no PR context; the flag lives on the commit. The comment carries a
#  hidden marker so re-runs update the same comment instead of stacking
#  duplicates, and a later clean run resolves it.
#
#  cest-analyzer exit codes, passed in as the first argument:
#    0  clean       - resolve any prior flag comment on this commit
#    1  regression  - post/update a commit comment flagging the commit
#    2  tool error  - no comment; any existing flag is left untouched
#
#  Uses the standard GitHub Actions environment (GITHUB_REPOSITORY, GITHUB_SHA,
#  GITHUB_REF_NAME, GITHUB_API_URL) plus a repo token in GH_TOKEN (pass
#  ${{ github.token }}). Posting a commit comment needs the job's
#  contents: write permission; without a usable token the script skips the
#  comment with a warning.
#
#  Usage: flag-profiling-results.sh <cest-exit-code> [summary-url]
#
#  summary-url: where the latest-vs-previous summary for this run can be read.
#  Defaults to the public result store root; pass the run-scoped URL once the
#  server-side summary endpoint is finalized.

set -eu

[ $# -ge 1 ] || { echo "usage: $0 <cest-exit-code> [summary-url]" >&2; exit 2; }
rc=$1
summary_url=${2:-https://cinfra-ca.inkbridge.io/profiling/data/}

marker='<!-- cest-perf-flag -->'
sha=${GITHUB_SHA:-unknown}
short=$(printf '%s' "$sha" | cut -c1-7)
ref=${GITHUB_REF_NAME:-${GITHUB_REF:-unknown}}

#  Only a regression creates a flag; a clean run resolves an existing one; a
#  tool error leaves any existing flag untouched.
case "$rc" in
1) echo "cest-analyzer flagged a regression (exit 1); flagging commit $short" ;;
0) echo "cest-analyzer clean (exit 0); resolving any prior flag on $short" ;;
*) echo "cest-analyzer exit $rc: no verdict, nothing to flag"; exit 0 ;;
esac

warn() { echo "::warning::flag-profiling-results: $*"; }

if [ -z "${GH_TOKEN:-}" ]; then warn "GH_TOKEN not set; skipping commit comment"; exit 0; fi
repo=${GITHUB_REPOSITORY:-}
if [ -z "$repo" ]; then warn "GITHUB_REPOSITORY not set; skipping commit comment"; exit 0; fi
api=${GITHUB_API_URL:-https://api.github.com}

#  Find an existing flag comment on this commit (by the hidden marker).
existing_id=$(curl -sS \
	-H "Authorization: Bearer $GH_TOKEN" \
	-H "Accept: application/vnd.github+json" \
	"$api/repos/$repo/commits/$sha/comments?per_page=100" \
	| jq -r --arg m "$marker" 'map(select(.body != null and (.body | contains($m)))) | .[0].id // empty') || existing_id=""

#  Build the comment body and JSON-encode it (jq handles all escaping).
if [ "$rc" = "1" ]; then
	body="$marker
:warning: CPU-cycle (CEst) regression detected in \`$ref\` @ \`$short\` vs the previous profiling run. [Latest-vs-previous summary]($summary_url)"
else
	#  rc = 0: nothing to say unless we are resolving a prior flag.
	[ -n "$existing_id" ] || exit 0
	body="$marker
:white_check_mark: Previously flagged CEst regressions in \`$ref\` @ \`$short\` are no longer present. [Latest-vs-previous summary]($summary_url)"
fi
payload=$(printf '%s' "$body" | jq -Rs '{body: .}')

resp=$(mktemp); trap 'rm -f "$resp"' EXIT
if [ -n "$existing_id" ]; then
	code=$(curl -sS -o "$resp" -w '%{http_code}' \
		-X PATCH -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" \
		-d "$payload" "$api/repos/$repo/comments/$existing_id") || code=000
	action="update"
else
	code=$(curl -sS -o "$resp" -w '%{http_code}' \
		-X POST -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" \
		-d "$payload" "$api/repos/$repo/commits/$sha/comments") || code=000
	action="create"
fi

case "$code" in
2??) echo "commit comment ${action}d (HTTP $code)" ;;
*)
	warn "could not $action commit comment (HTTP $code)"
	[ -s "$resp" ] && cat "$resp" >&2
	;;
esac

#  Advisory: never fail the build on a commenting problem.
exit 0
