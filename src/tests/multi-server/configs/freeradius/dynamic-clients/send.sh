#!/bin/bash
#
#  Send one radclient request from the client container and report the
#  outcome as a test framework trigger.
#
#  Usage:
#    send.sh [--attempts N] [--timeout T] [--source O] <step> <server[:port]> <auth|status|coa|disconnect> <secret> [radclient options] -- <attribute pair>...
#
#  The script writes the attribute pairs to the stdin of radclient, one per
#  line.  When radclient exits, the script appends the line
#
#    client-<step> {"exit_code": N, "attempts": N, "reply_count": N, "replies": "<codes>"}
#
#  to the file that the test framework watches.  `replies` lists the
#  distinct reply packet codes that radclient received, comma separated, and
#  is empty when no reply arrived.  radclient exits non-zero when the server
#  does not answer a request.
#
#  With `--source O`, radclient binds to the alias of the container whose
#  address ends in the octet O, so the request arrives at the server from
#  an address that the server has not seen.  Without the option radclient
#  binds to the container address.
#
#  radclient waits `--timeout T` seconds for a reply (default one second)
#  and does not retransmit, so a dropped request costs T seconds.  The test
#  raises T when the server runs under a profiler.  With `--attempts N`, the
#  script sends the request again after each unanswered attempt, up to N
#  times.  The `attempts` field reports the number of attempts that the
#  script made.  A case uses the resends to wait for a condition on the
#  server, such as the expiry of a negative cache entry.  radclient exits
#  after T seconds without a reply, so consecutive attempts are T seconds
#  apart.
#
set -u

attempts_max=1
reply_timeout=1
source_octet=0
while true; do
	case "$1" in
	--attempts)
		attempts_max=$2
		shift 2
		;;
	--timeout)
		reply_timeout=$2
		shift 2
		;;
	--source)
		source_octet=$2
		shift 2
		;;
	*)
		break
		;;
	esac
done

step=$1
target=$2
command=$3
secret=$4
shift 4

options=()
while [ $# -gt 0 ] && [ "$1" != "--" ]; do
	options+=("$1")
	shift
done
if [ $# -gt 0 ]; then
	shift
fi

trigger_file="/var/run/multi-server/${TEST_PROJECT_NAME}.txt"

if [ "$source_octet" -gt 0 ]; then
	own=$(ip -4 -o addr show dev eth0 | head -1 | awk '{print $4}' | cut -d/ -f1)
	options+=(-C "${own%.*}.${source_octet}:$((20000 + RANDOM % 20000))")
fi

attempt=0
while true; do
	attempt=$((attempt + 1))
	output=$(printf '%s\n' "$@" | radclient -x -t "$reply_timeout" -r 1 "${options[@]}" "$target" "$command" "$secret" 2>&1)
	exit_code=$?
	printf '%s\n' "$output"
	if [ $exit_code -eq 0 ] || [ $attempt -ge "$attempts_max" ]; then
		break
	fi
done

replies=$(printf '%s\n' "$output" | sed -n 's/^Received \([A-Za-z-]*\) .*/\1/p')
reply_count=$(printf '%s\n' "$replies" | grep -c .)
reply_codes=$(printf '%s\n' "$replies" | grep . | sort -u | paste -sd, -)

echo "client-${step} {\"exit_code\": ${exit_code}, \"attempts\": ${attempt}, \"reply_count\": ${reply_count}, \"replies\": \"${reply_codes}\"}" >> "$trigger_file"
