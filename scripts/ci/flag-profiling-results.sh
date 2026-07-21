#!/bin/sh
#
#  Flag the latest profiling results. Writes the cest-analyzer regression report
#  to the GitHub Actions job summary, and on a regression posts (or updates) a
#  commit comment on the current commit. Advisory only: a commenting failure
#  warns but never fails the build, so this is safe to run continue-on-error
#  after the cest-analyzer gate step.
#
#  This workflow runs on push, so there is no PR context; the flag lives on the
#  commit. The comment carries a hidden marker so re-runs update the same
#  comment instead of stacking duplicates, and a later clean run resolves it.
#
#  cest-analyzer exit codes, passed in as the first argument:
#    0  clean       - summary says clean; resolve any prior flag comment
#    1  regression  - summary + a commit comment flagging the commit
#    2  tool error  - summary notes the error; no comment
#
#  Uses the standard GitHub Actions environment (GITHUB_STEP_SUMMARY,
#  GITHUB_REPOSITORY, GITHUB_SHA, GITHUB_REF_NAME, GITHUB_API_URL) plus a repo
#  token in GH_TOKEN (pass ${{ github.token }}). Posting a commit comment needs
#  the job's contents: write permission; without a usable token the script
#  still writes the job summary and skips the comment with a warning.
#
#  Usage: flag-profiling-results.sh <cest-exit-code> <report-md-file> [dashboard-url] [store-url]

set -eu

[ $# -ge 2 ] || { echo "usage: $0 <cest-exit-code> <report-md-file> [dashboard-url] [store-url]" >&2; exit 2; }
rc=$1
report_file=$2
#  The default dashboard link carries the gate's size floor (?floor=), so a
#  reader clicking through from a flag sees the same view the gate scored.
#  Keep the value in sync with the workflow's --min-cest.
dashboard=${3:-https://cinfra-ca.inkbridge.io/profiling/dashboard/?floor=10M}
store=${4:-https://cinfra-ca.inkbridge.io/profiling/data/}

#  Footer links shown in the summary and the commit comment: the dashboard to
#  read the run, and the raw result store to browse the published files.
links="[InkScope dashboard]($dashboard) | [Result store]($store)"

marker='<!-- cest-perf-flag -->'
sha=${GITHUB_SHA:-unknown}
short=$(printf '%s' "$sha" | cut -c1-7)
ref=${GITHUB_REF_NAME:-${GITHUB_REF:-unknown}}
header="### CPU-cycle profiling (CEst): \`$ref\` @ \`$short\`"

#  The report body may be absent (e.g. a tool error produced no file).
report=""
[ -f "$report_file" ] && report=$(cat "$report_file")

#  ---- 1. Job summary, written every run ----------------------------------
summary=$(mktemp)
trap 'rm -f "$summary"' EXIT
{
	printf '%s\n\n' "$header"
	case "$rc" in
	1)
		if [ -n "$report" ]; then printf '%s\n' "$report"
		else printf '%s\n' "_A regression was flagged but no report file was produced._"; fi
		printf '\n%s\n' "$links"
		;;
	2)
		printf '%s\n' ":warning: cest-analyzer reported a tool error (exit 2); no regression verdict this run."
		;;
	0)
		printf '%s\n\n%s\n' \
			"No CEst regressions past the gate. :white_check_mark:" "$links"
		;;
	*)
		printf '%s\n' "cest-analyzer produced no verdict (exit ${rc:-unknown})."
		;;
	esac
} >"$summary"

[ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$summary" >>"$GITHUB_STEP_SUMMARY"
cat "$summary"

#  ---- 2. Commit comment, best effort -------------------------------------
#  Only a regression creates a flag; a clean run resolves an existing one; a
#  tool error leaves any existing flag untouched.
if [ "$rc" != "1" ] && [ "$rc" != "0" ]; then
	exit 0
fi

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
	if [ -n "$report" ]; then body="$marker
$header

$report

$links"
	else body="$marker
$header

_A regression was flagged._

$links"; fi
else
	#  rc = 0: nothing to say unless we are resolving a prior flag.
	[ -n "$existing_id" ] || exit 0
	body="$marker
$header

Previously flagged CEst regressions are no longer present; latest run is clean. :white_check_mark:

$links"
fi
payload=$(printf '%s' "$body" | jq -Rs '{body: .}')

resp=$(mktemp); trap 'rm -f "$summary" "$resp"' EXIT
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
