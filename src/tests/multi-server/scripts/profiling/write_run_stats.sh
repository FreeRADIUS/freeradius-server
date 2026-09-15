#!/bin/bash
#
#  Write the statistics of one profiling run into PROFILING_RESULT_DIR.
#
#  load-stats.csv is the exact copy of the proto_load stats.
#
#  run-stats.json has:
#   - proto_load configuration the run used from TEST_LOADGEN_* env variables
#   - number of packets sent and received
#   - metric type cest/cpu_time
#   - image used for the run
#   - cflags used
#   - sampling frequency (only valid for cpu_time metric type)
#   - profiler options used
#
#  The capture script runs this script as
#
#    write_run_stats.sh <tool> [<server-log>]
#
#  <server-log> defaults to PROFILING_RESULT_DIR/freeradius.log
#

set -u

usage()
{
	cat <<EOF
Usage: ${0##*/} <tool> [<server-log>]

Write load-stats.csv and run-stats.json for one profiling run into
PROFILING_RESULT_DIR.  Both capture scripts run this script after the
profiled server exits.

  <tool>        Profiler that produced the run: valgrind or gperftools.
  <server-log>  Server stdout and stderr to read the proto_load completion
                line from.  Default: PROFILING_RESULT_DIR/freeradius.log.
  -h            Show this help.

Environment, set by the compose file:
  PROFILING_RESULT_DIR  (Required) Directory that receives the output.
  FREERADIUS_IMAGE      (Optional) Image tag recorded in capture.image.
  TEST_LOADGEN_*        (Optional) proto_load configuration recorded in loadgen.

Environment, set by the capture script:
  METRIC_KIND       (Required) cest for callgrind, cpu_time for gperftools
  SAMPLING_HZ       (Optional) Samples per CPU-second, unset for callgrind.
  PROFILER_OPTIONS  (Optional) Command line options used with profiler.
  EXIT_STATUS       (Optional) Exit status of the profiled server, the same
                    value the capture script writes to exit-status.
  DURATION_S        (Optional) Seconds from the start of the server to the
                    exit of the server.
EOF
}

case ${1:-} in
-h|--help)
	usage
	exit 0
	;;
esac

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
	usage >&2
	exit 2
fi

: "${PROFILING_RESULT_DIR:?set PROFILING_RESULT_DIR to the directory that receives the profiling output}"
: "${METRIC_KIND:?set METRIC_KIND to cest or cpu_time}"
TOOL=$1
RESULTS=$PROFILING_RESULT_DIR
SERVER_LOG=${2:-$RESULTS/freeradius.log}

#  Save the proto_load stats CSV file to the results directory
#  if it exists.  Hardcoded to same path set in the docker compose file
#  for the container.
LOADGEN_CSV=/etc/freeradius/stats/load-generator-stats.csv
if [ -s "$LOADGEN_CSV" ]; then
  cp "$LOADGEN_CSV" "$RESULTS/load-stats.csv"
  echo "INFO: wrote load-stats.csv"
else
  echo "WARNING: skipping load-generator stats, no CSV file ${LOADGEN_CSV} detected"
  LOADGEN_CSV=/dev/null
fi

#
#  proto_load logs the exact packet totals on completion.  The final row of
#  the CSV can lag the totals by up to one second of traffic, so the totals
#  come from the log line.  proto_load logs the line once the pps ramp has
#  passed max_pps and every reply has arrived.  max_requests only adds a
#  packet count to the completion condition, and the test suites leave
#  max_requests at 0.  An absent line means that the load never completed.
#
read -r COMPLETED_SENT COMPLETED_RECEIVED <<< "$(sed -n \
  's/.*Load test for .* complete - sent \([0-9]*\) packets, received \([0-9]*\) replies.*/\1 \2/p' \
  "$SERVER_LOG" 2>/dev/null | head -1)"

#  The awk program indexes the CSV columns by position, so the script skips
#  a CSV whose header does not match the header that
#  fr_load_generator_stats_sprint writes.
LOADGEN_HEADER='"time","last_packet","rtt","rttvar","pps","pps_accepted","sent","received","backlog","max_backlog","<usec","us","10us","100us","ms","10ms","100ms","s","blocked"'
if [ "$LOADGEN_CSV" != /dev/null ] && [ "$(head -1 "$LOADGEN_CSV")" != "$LOADGEN_HEADER" ]; then
  echo "WARNING: leaving the final CSV row out of run-stats.json, unexpected load-generator CSV header"
  LOADGEN_CSV=/dev/null
fi

#  The profiling image contains the source tree of the build, and config.log
#  in the tree records the CFLAGS that configure received.
CFLAGS=$(sed -n "s/.*'CFLAGS=\([^']*\)'.*/\1/p" \
  /usr/local/src/repositories/freeradius-server/config.log 2>/dev/null | head -1)

#  Quote a string for JSON, or print null when the string is empty.
json_string() {
  if [ -z "$1" ]; then
    printf 'null'
  else
    printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  fi
}

#
#  awk processes escape sequences in -v values, and the processing would
#  undo the JSON quoting.  The script therefore passes the quoted strings
#  through the environment, and passes the numbers and the bare words as
#  -v values.
#
JSON_IMAGE=$(json_string "${FREERADIUS_IMAGE:-}") \
JSON_CFLAGS=$(json_string "$CFLAGS") \
JSON_PROFILER_OPTIONS=$(json_string "${PROFILER_OPTIONS:-}") \
awk -F, \
  -v tool="$TOOL" \
  -v start_pps="${TEST_LOADGEN_START_PPS:-0}" \
  -v max_pps="${TEST_LOADGEN_MAX_PPS:-0}" \
  -v duration="${TEST_LOADGEN_DURATION:-0}" \
  -v step="${TEST_LOADGEN_STEP:-0}" \
  -v parallel="${TEST_LOADGEN_PARALLEL:-0}" \
  -v max_backlog="${TEST_LOADGEN_MAX_BACKLOG:-0}" \
  -v max_requests="${TEST_LOADGEN_MAX_REQUESTS:-0}" \
  -v on_complete="${TEST_LOADGEN_COMPLETE:-}" \
  -v completed_sent="${COMPLETED_SENT:-}" \
  -v completed_received="${COMPLETED_RECEIVED:-}" \
  -v exit_status="${EXIT_STATUS:-null}" \
  -v duration_s="${DURATION_S:-null}" \
  -v metric_kind="$METRIC_KIND" \
  -v sampling_hz="${SAMPLING_HZ:-null}" \
  'NR > 1 { last = $0 }
   END {
     printf "{\n"
     printf "  \"version\": 1,\n"
     printf "  \"tool\": \"%s\",\n", tool
     printf "  \"loadgen\": {\"start_pps\": %d, \"max_pps\": %d, \"duration\": %d, \"step\": %d, \"parallel\": %d, \"max_backlog\": %d, \"max_requests\": %d, \"on_complete\": \"%s\"},\n", \
            start_pps, max_pps, duration, step, parallel, max_backlog, max_requests, on_complete
     if (completed_sent != "") {
       printf "  \"completion\": {\"logged\": true, \"sent\": %s, \"received\": %s},\n", completed_sent, completed_received
     } else {
       printf "  \"completion\": {\"logged\": false},\n"
     }
     if (last != "") {
       split(last, f, ",")
       printf "  \"final\": {\"time\": %s, \"last_packet\": %s, \"rtt\": %s, \"rttvar\": %s, \"pps\": %s, \"pps_accepted\": %s, \"sent\": %s, \"received\": %s, \"backlog\": %s, \"max_backlog\": %s, \"times\": [%s, %s, %s, %s, %s, %s, %s, %s], \"blocked\": %s},\n", \
              f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], \
              f[11], f[12], f[13], f[14], f[15], f[16], f[17], f[18], f[19]
     } else {
       printf "  \"final\": null,\n"
     }
     printf "  \"process\": {\"exit_status\": %s, \"duration_s\": %s},\n", exit_status, duration_s
     printf "  \"capture\": {\n"
     printf "    \"metric_kind\": \"%s\",\n", metric_kind
     printf "    \"image\": %s,\n", ENVIRON["JSON_IMAGE"]
     printf "    \"cflags\": %s,\n", ENVIRON["JSON_CFLAGS"]
     printf "    \"sampling_frequency_hz\": %s,\n", sampling_hz
     printf "    \"profiler_options\": %s\n", ENVIRON["JSON_PROFILER_OPTIONS"]
     printf "  }\n"
     printf "}\n"
   }' "$LOADGEN_CSV" > "$RESULTS/run-stats.json" \
  || { echo "ERROR: could not write ${RESULTS}/run-stats.json"; exit 1; }

echo "INFO: wrote run-stats.json"
