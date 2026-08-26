#!/bin/sh
#
#  Start a Kafka subscriber in the background for rlm_kafka tests.
#
#  Invoked once at the top of a test to set up the subscription:
#   - resets the topic (so `-o start` below only sees what this test is
#     about to produce, not leftovers from a previous run),
#   - forks `rpk topic consume -n COUNT -o start` into the background,
#     writing one JSON line per record into OUT_FILE as records arrive,
#   - returns to the caller immediately.
#
#  The companion kafka-wait-and-cleanup.sh tails OUT_FILE with `tail -F`, so records
#  are visible to the waiting test as soon as rpk flushes them - no
#  intermediate tempfile, no atomic rename, and no sleep loop anywhere.
#  Wrap kafka-wait-and-cleanup invocations in an unlang `timeout Ns { }` block to
#  bound how long the test is willing to stand for a stuck broker.
#
#  Usage:
#    kafka-subscribe TOPIC OUTPUT_FILE COUNT
#
#  Env:
#    KAFKA_TEST_BROKER_CONTAINER  Docker container name of the broker
#                                 (default: fr-kafka).
#
#  Output: one compact JSON object per line (no outer array), with
#  value / key base64-encoded so arbitrary byte payloads round-trip
#  intact.  kafka-wait-and-cleanup.sh assembles the final JSON array from these
#  lines once the subscriber has seen enough of them.

set -eu

TOPIC=${1:?"topic required"}
OUT=${2:?"output file required"}
COUNT=${3:?"count required"}
CONTAINER=${KAFKA_TEST_BROKER_CONTAINER:-fr-kafka}

FORMAT='{"topic":"%t","value":"%v{base64}","key":"%k{base64}","offset":%o,"partition":%p,"timestamp":%d}\n'

#
#  Reset the topic so `-o start` in rpk only sees what the test is
#  about to produce.  `|| true` covers the first-ever invocation when
#  no topic exists yet.
#
docker exec "$CONTAINER" rpk topic delete "$TOPIC" >/dev/null 2>&1 || true
docker exec "$CONTAINER" rpk topic create "$TOPIC" >/dev/null 2>&1

#
#  Remove any leftover output so kafka-wait-and-cleanup.sh's `tail -F` doesn't
#  start reading stale data from a previous run.
#
rm -f -- "$OUT"
: >"$OUT"

#
#  Fork rpk into the background.  It writes JSON lines straight to
#  OUT as they arrive and exits cleanly when it has drained COUNT
#  records.  Fully detached from the caller's stdio so the test
#  harness doesn't block here.
#
docker exec "$CONTAINER" rpk topic consume "$TOPIC" \
	-n "$COUNT" \
	-o start \
	--format "$FORMAT" \
	>>"$OUT" 2>/dev/null </dev/null &

#
#  Record the host-side `docker exec` pid so kafka-wait-and-cleanup.sh can reap it
#  on exit.  Without this, a test that fails before COUNT records
#  arrive would leak the subscriber until the next test's topic reset.
#
printf '%s\n' "$!" >"$OUT.pid"

exit 0
