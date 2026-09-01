#!/bin/bash
#
#  Kafka consumer for the multi-server "kafka-produce" test.
#
#  Blocks until TEST_EXPECTED_MESSAGES records have been consumed from the
#  configured topic (or TEST_CONSUMER_TIMEOUT seconds elapse), writing one
#  listener line per received message plus a single summary line at the end.
#
#  Environment:
#    TEST_PROJECT_NAME       - docker compose project name (listener filename)
#    TEST_KAFKA_BROKER       - host:port of the broker
#    TEST_KAFKA_TOPIC        - topic to consume from
#    TEST_EXPECTED_MESSAGES  - how many messages are expected
#    TEST_CONSUMER_TIMEOUT   - overall timeout in seconds
#
set -u

LISTENER="/var/run/multi-server/${TEST_PROJECT_NAME}.txt"
EXPECTED="${TEST_EXPECTED_MESSAGES:-0}"

#
#  `TEST_CONSUMER_TIMEOUT` must undercut the verify window of the state
#  that waits on the summary.  consume.sh writes the summary below only
#  after kcat finishes.  A consumer that outlives the state writes the
#  summary after teardown has removed the listener file, so the test
#  framework reports "<no events seen>" instead of a received/expected
#  count.
#
TIMEOUT="${TEST_CONSUMER_TIMEOUT:-20}"
BROKER="${TEST_KAFKA_BROKER:-kafka:9092}"
TOPIC="${TEST_KAFKA_TOPIC:-fr-multi-server-test}"

#
#  Wait for the listener file to exist.  FreeRADIUS's linelog module creates
#  it on startup; if we write before it exists the test framework's fsnotify
#  loop won't see our writes.
#
waited=0
while [ ! -e "$LISTENER" ]; do
	if [ "$waited" -ge 30 ]; then
		printf 'consume.sh: listener file %s never appeared\n' "$LISTENER" >&2
		exit 1
	fi
	sleep 1
	waited=$((waited + 1))
done

#
#  jq isn't available in the cp-kcat image, but payloads are plain ASCII
#  strings we control (Access-Request User-Names).  Escape backslashes and
#  double quotes for JSON safety; anything outside a narrow ASCII subset
#  should never appear in practice, but escape it defensively.
#
json_escape() {
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	printf '%s' "$s"
}

#
#  The loop consumes `EXPECTED` messages, or stops on timeout.  kcat
#  prints each message payload followed by a newline because of `-D`.
#  When fewer than `EXPECTED` messages arrive, kcat blocks until
#  `timeout` kills kcat.  The loop then ends, and the script still
#  writes the FAIL summary below.
#
count=0
while IFS= read -r payload; do
	count=$((count + 1))
	escaped="$(json_escape "$payload")"
	printf 'kafka-consumer-received {"seq": %d, "payload": "%s"}\n' \
	       "$count" "$escaped" >> "$LISTENER"

	if [ "$count" -ge "$EXPECTED" ]; then
		break
	fi
done < <(timeout "$TIMEOUT" kcat \
			-b "$BROKER" \
			-t "$TOPIC" \
			-C \
			-o beginning \
			-c "$EXPECTED" \
			-q \
			-D $'\n' \
			2>&2)

#
#  Emit a single summary line the test framework matches on.  PASS if we got
#  everything we expected, FAIL otherwise.
#
result="FAIL"
if [ "$count" -eq "$EXPECTED" ]; then
	result="PASS"
fi

printf 'kafka-consumer-summary {"received": %d, "expected": %d, "result": "%s"}\n' \
       "$count" "$EXPECTED" "$result" >> "$LISTENER"

#
#  Keep the container alive so the test framework can inspect logs if
#  something went wrong.  The test is complete at this point regardless.
#
sleep infinity
