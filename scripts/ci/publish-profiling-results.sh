#!/bin/sh
#
#  Tar up the prof-results/ directory (if any) and POST the tarball, with a
#  GitHub OIDC bearer token, to the URL given as the only argument. A missing
#  or empty prof-results/ is a quiet exit 0. Transient outcomes (curl command
#  failure, 408, 429, 5xx) when trying to obtain an OIDC token or upload the
#  tarball exit 75 (EX_TEMPFAIL), which the CI step tolerates; any other
#  failure exits non-zero so the CI leg fails with it.
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

Fails without publishing when any test's exit-status is non-zero, because a
capture the profiler did not finish cleanly has truncated output whose numbers
are not comparable with previous runs.

  <url>  Where to POST. Its origin becomes the OIDC audience.
  -h     Show this help.

Needs ACTIONS_ID_TOKEN_REQUEST_TOKEN and ACTIONS_ID_TOKEN_REQUEST_URL, which
the runner sets when the job has "id-token: write".

Exit status:
  0   published, or nothing to publish
  1   refused an unclean capture, a missing commit subject, GITHUB_REF_NAME
      or OIDC request variable, the server refused the token request or upload,
      or returned no token
  2   usage error
  75  transient outcomes (curl command failure, 408, 429, 5xx) when trying to
      obtain an OIDC token or upload the tarball

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

#  Exit status for a failed token request or upload. Use standard exit code
#  representing a temporary failure with EX_TEMPFAIL=75.
EX_TEMPFAIL=75
url=$1

#  The OIDC audience is the URL's origin (scheme://host).
host_path=${url#*://}
audience="${url%%://*}://${host_path%%/*}"

[ -d prof-results ] || { echo "no prof-results/ tree; skipping"; exit 0; }

#  Refuse to publish a capture the profiler did not finish cleanly. Each
#  capture script drops an exit-status file in its result dir; a non-zero
#  status means the profiler was killed, which leaves the output truncated at
#  whatever point it died. Numbers from a truncated run are not comparable
#  with a clean one, and publishing them silently poisons the
#  per-suite history the regression gate compares against. Exits non-zero so
#  the leg goes red rather than passing with nothing uploaded.
unclean=""
for status_file in $(find prof-results -type f -name exit-status | sort); do
	read -r status <"$status_file" || status="unreadable"
	case $status in
	0)	continue ;;
	esac
	unclean="${unclean} ${status_file%/exit-status}:${status}"
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

#  Mint the OIDC token. curl retries timeouts, refused connections and HTTP
#  408/429/5xx once, two seconds apart. Each attempt gets 10
#  seconds to connect and 30 seconds in total.
#
#  --no-progress-meter keeps errors and retry warnings in the logs.
#  -w logs the HTTP code and how long the last attempt took.
if [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] || [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
	echo "ERROR: ACTIONS_ID_TOKEN_REQUEST_* not set; the job needs \"id-token: write\"" >&2
	exit 1
fi

token_resp="$tmpdir/token-response"
token_code=$(curl --no-progress-meter --connect-timeout 10 --max-time 30 \
	--retry 1 --retry-delay 2 --retry-connrefused \
	-o "$token_resp" -w '%{http_code}%{stderr}token request: %{time_total}s\n' \
	--oauth2-bearer "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
	"$ACTIONS_ID_TOKEN_REQUEST_URL&audience=${audience}") || token_code=000

case "$token_code" in
	2??)
		# If jq fails, set token to empty and continue. Important
		# to do since we are using set -e and we do not want to exit
		# when jq fails.
		token=$(jq -r '.value // empty' "$token_resp") || token=
		;;
	000|408|429|5??)
		echo "ERROR: could not obtain OIDC token (HTTP $token_code)" >&2
		[ -s "$token_resp" ] && { cat "$token_resp" >&2; echo >&2; }
		exit $EX_TEMPFAIL
		;;
	*)
		echo "ERROR: could not obtain OIDC token (HTTP $token_code)" >&2
		[ -s "$token_resp" ] && { cat "$token_resp" >&2; echo >&2; }
		exit 1
		;;
esac

#  Check that token has a value
if [ -z "$token" ]; then
	echo "ERROR: OIDC token is empty" >&2
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
#  The upload gets 10 seconds to connect and 120 seconds in total.
code=$(curl -sS --connect-timeout 10 --max-time 120 -o "$resp" -w '%{http_code}' \
	-X POST --oauth2-bearer "$token" \
	-H "X-Prof-Commit-Subject-B64: $subject_b64" \
	-H "X-Prof-Branch-Ref-B64: $branch_b64" \
	--data-binary @"$tarball" \
	"$url") || code=000

case "$code" in
	2??)
		exit 0
		;;
	000|408|429|5??)
		echo "ERROR: publish failed (HTTP $code)" >&2
		[ -s "$resp" ] && { cat "$resp" >&2; echo >&2; }
		exit $EX_TEMPFAIL
		;;
	4??)
		echo "ERROR: publish failed (HTTP $code)" >&2
		[ -s "$resp" ] && { cat "$resp" >&2; echo >&2; }
		exit 1
		;;
	*)
		echo "ERROR: unexpected publish failure (HTTP $code)" >&2
		[ -s "$resp" ] && { cat "$resp" >&2; echo >&2; }
		exit 1
		;;
esac
