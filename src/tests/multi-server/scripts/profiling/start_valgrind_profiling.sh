#!/bin/bash

# To be run inside the profiling container

# Clear any stale marker from a previous run
rm -f /etc/prof-results/.profiling_complete
rm -f /etc/prof-results/valgrind_profiling.log

exec > /etc/prof-results/valgrind_profiling.log 2>&1

# Ignore SIGTERM — freeradius broadcasts it to the process group on shutdown,
# which would otherwise kill this script before it can touch .profiling_complete.
# As a side-effect `docker stop` cannot tear this script down before the
# 10s SIGKILL fallback.
trap '' SIGTERM

# Echo env variables required for proto_load configuration and test load generation — these should be set by the testcase template
echo "proto_load configuration environment variables:"
echo "TEST_LOADGEN_START_PPS=$TEST_LOADGEN_START_PPS"
echo "TEST_LOADGEN_MAX_PPS=$TEST_LOADGEN_MAX_PPS"
echo "TEST_LOADGEN_DURATION=$TEST_LOADGEN_DURATION"
echo "TEST_LOADGEN_STEP=$TEST_LOADGEN_STEP"
echo "TEST_LOADGEN_PARALLEL=$TEST_LOADGEN_PARALLEL"
echo "TEST_LOADGEN_MAX_BACKLOG=$TEST_LOADGEN_MAX_BACKLOG"
echo "TEST_LOADGEN_REPEAT=$TEST_LOADGEN_REPEAT"
echo "TEST_LOADGEN_MAX_REQUESTS=$TEST_LOADGEN_MAX_REQUESTS"
echo ""

# Approximate load-generator send duration; the instrumented run sleeps this
# long between callgrind_control --instr=on and the graceful shutdown signal.
SEND_DURATION=$(( TEST_LOADGEN_MAX_REQUESTS / TEST_LOADGEN_START_PPS ))

# Start freeradius under valgrind with instrumentation off.
#
# valgrind logs to --log-file; freeradius stdout/stderr go to freeradius.log.
# No `| tee`: the fallback kill paths below need $! to be the valgrind PID,
# not tee's.
#
# --trace-children=yes    profile exec()'d children too (own callgrind.out.%p)
# --separate-threads=no   one profile per process, not per thread
# --separate-callers=6    split a function's costs by up to 6 callers deep
# --dump-instr=yes        per-instruction counts (assembly-level inspection)
# --collect-jumps=yes     record jumps for intra-function control flow
# --cache-sim=yes         cache counters (Dr/Dw + L1/LL misses) for CEst
# --branch-sim=yes        branch mispredict counters (Bc/Bi) for CEst
# --keep-debuginfo=yes    keep symbols of dlclose'd code for late dumps
# --instr-atstart=no      start uninstrumented; enabled below once the server
#                         is ready, keeping startup out of the profile
valgrind \
  --tool=callgrind \
  --log-file=/etc/prof-results/valgrind.log \
  --callgrind-out-file=/etc/prof-results/callgrind.out.%p \
  --trace-children=yes \
  --separate-threads=no \
  --separate-callers=6 \
  --dump-instr=yes \
  --collect-jumps=yes \
  --cache-sim=yes \
  --branch-sim=yes \
  --keep-debuginfo=yes \
  --instr-atstart=no \
  freeradius -f -l stdout -S resources.talloc_skip_cleanup=yes \
  > /etc/prof-results/freeradius.log 2>&1 &
VALGRIND_PID=$!

# Wait for server ready (bail out if freeradius fails to start under valgrind)
STARTUP_TIMEOUT=300
STARTUP_ELAPSED=0
until grep -q "Ready to process requests" /etc/prof-results/freeradius.log; do
  sleep 1
  STARTUP_ELAPSED=$(( STARTUP_ELAPSED + 1 ))
  if [ ${STARTUP_ELAPSED} -ge ${STARTUP_TIMEOUT} ]; then
    echo "ERROR: freeradius did not become ready within ${STARTUP_TIMEOUT}s, aborting"
    kill -SIGKILL ${VALGRIND_PID} 2>/dev/null
    exit 1
  fi
done

# Enable instrumentation. callgrind_control auto-detects the running callgrind
# instance and prints "PID <n>: freeradius ..." — capture that to get the PID
# we need later for the graceful shutdown signal.
echo "INFO: enabling callgrind instrumentation"
CTRL_OUT=$(callgrind_control --instr=on)
printf '%s\n' "$CTRL_OUT"
FR_PID=$(printf '%s\n' "$CTRL_OUT" | grep -oP 'PID \K\d+(?=: freeradius)' | head -1)
echo "Freeradius PID: ${FR_PID}"

# Wait for approximate send duration
sleep ${SEND_DURATION}

# Graceful shutdown (equivalent to Ctrl+C) — keep instrumentation on so shutdown
# transitions are captured before we stop profiling
SHUTDOWN_ELAPSED=0
SHUTDOWN_TIMED_OUT=false
if [ -z "${FR_PID}" ]; then
  echo "WARNING: could not determine freeradius PID from callgrind_control output, sending SIGINT to valgrind instead"
  kill -SIGINT ${VALGRIND_PID} 2>/dev/null || true
else
  echo "INFO: killing freeradius process ${FR_PID} with SIGINT for graceful shutdown"
  kill -SIGINT ${FR_PID}

  # Wait for freeradius to finish its graceful shutdown before stopping instrumentation
  SHUTDOWN_TIMEOUT=60
  while kill -0 "${FR_PID}" 2>/dev/null; do
    sleep 1
    SHUTDOWN_ELAPSED=$(( SHUTDOWN_ELAPSED + 1 ))
    if [ ${SHUTDOWN_ELAPSED} -ge ${SHUTDOWN_TIMEOUT} ]; then
      echo "WARNING: freeradius did not exit within ${SHUTDOWN_TIMEOUT}s after SIGINT"
      SHUTDOWN_TIMED_OUT=true
      break
    fi
  done
  echo "INFO: freeradius exited after ${SHUTDOWN_ELAPSED}s"
fi

# Stop instrumentation after graceful shutdown so all shutdown transitions are captured
echo "INFO: disabling callgrind instrumentation"
CTRL_OUT=$(callgrind_control --instr=off 2>/dev/null || true)
printf '%s\n' "$CTRL_OUT"

# Wait for valgrind to finish writing callgrind output. Record how it exited:
# a run valgrind killed produces truncated callgrind output whose numbers are
# not comparable with a clean run, so the status has to survive to the publish
# step, which reads this file and refuses to upload an unclean run. The status
# is recorded for clean runs too, so an absent file means "the wrapper did not
# get this far" rather than "the run was fine".
echo "INFO: waiting for valgrind to exit"
VALGRIND_STATUS=0
wait ${VALGRIND_PID} 2>/dev/null || VALGRIND_STATUS=$?
echo "${VALGRIND_STATUS}" > /etc/prof-results/valgrind-exit-status

if [ "${VALGRIND_STATUS}" -ne 0 ]; then
  #  Over 128 means a signal. 139 is SIGSEGV, which is how valgrind exiting on
  #  its 8 MB brk segment ceiling presents; valgrind.log names the real reason
  #  on the line above its backtrace.
  if [ "${VALGRIND_STATUS}" -gt 128 ]; then
    echo "ERROR: valgrind was killed by signal $((VALGRIND_STATUS - 128)); profiling data is truncated" >&2
  else
    echo "ERROR: valgrind exited ${VALGRIND_STATUS}; profiling data may be truncated" >&2
  fi
  echo "ERROR: see valgrind.log for the reason; these results will not be published" >&2
fi

# Signal that valgrind has finished writing all profiling data
echo "INFO: Profiling complete at $(date)"

# Publish load-generator stats: the per-second CSV plus run-stats.json
# (loadgen config, final CSV row totals, script phase timings).
echo "INFO: publishing load-generator stats"
LOADGEN_CSV=/etc/freeradius/stats/load-generator-stats.csv
if [ -s "${LOADGEN_CSV}" ]; then
  cp "${LOADGEN_CSV}" /etc/prof-results/load-stats.csv
else
  echo "WARNING: no load-generator stats CSV at ${LOADGEN_CSV}"
  LOADGEN_CSV=/dev/null
fi

# The awk below indexes columns by position: refuse a CSV whose header no
# longer matches what fr_load_generator_stats_sprint writes.
LOADGEN_HEADER='"time","last_packet","rtt","rttvar","pps","pps_accepted","sent","received","backlog","max_backlog","<usec","us","10us","100us","ms","10ms","100ms","s","blocked"'
if [ "${LOADGEN_CSV}" != /dev/null ] && [ "$(head -1 "${LOADGEN_CSV}")" != "${LOADGEN_HEADER}" ]; then
  echo "WARNING: unexpected load-generator CSV header; run totals left out of run-stats.json"
  LOADGEN_CSV=/dev/null
fi

awk -F, \
  -v start_pps="${TEST_LOADGEN_START_PPS}" \
  -v max_pps="${TEST_LOADGEN_MAX_PPS}" \
  -v duration="${TEST_LOADGEN_DURATION}" \
  -v step="${TEST_LOADGEN_STEP}" \
  -v parallel="${TEST_LOADGEN_PARALLEL}" \
  -v max_backlog="${TEST_LOADGEN_MAX_BACKLOG}" \
  -v num_messages="${TEST_LOADGEN_NUM_MESSAGES}" \
  -v startup_s="${STARTUP_ELAPSED}" \
  -v send_wait_s="${SEND_DURATION}" \
  -v shutdown_s="${SHUTDOWN_ELAPSED}" \
  -v shutdown_timed_out="${SHUTDOWN_TIMED_OUT}" \
  'NR > 1 { last = $0 }
   END {
     printf "{\n"
     printf "  \"version\": 1,\n"
     printf "  \"loadgen\": {\"start_pps\": %d, \"max_pps\": %d, \"duration\": %d, \"step\": %d, \"parallel\": %d, \"max_backlog\": %d, \"num_messages\": %d},\n", \
            start_pps, max_pps, duration, step, parallel, max_backlog, num_messages
     if (last != "") {
       split(last, f, ",")
       printf "  \"final\": {\"time\": %s, \"last_packet\": %s, \"rtt\": %s, \"rttvar\": %s, \"pps\": %s, \"pps_accepted\": %s, \"sent\": %s, \"received\": %s, \"backlog\": %s, \"max_backlog\": %s, \"times\": [%s, %s, %s, %s, %s, %s, %s, %s], \"blocked\": %s},\n", \
              f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], \
              f[11], f[12], f[13], f[14], f[15], f[16], f[17], f[18], f[19]
     } else {
       printf "  \"final\": null,\n"
     }
     printf "  \"phases\": {\"startup_s\": %d, \"send_wait_s\": %d, \"shutdown_s\": %d, \"shutdown_timed_out\": %s}\n", \
            startup_s, send_wait_s, shutdown_s, shutdown_timed_out
     printf "}\n"
   }' "${LOADGEN_CSV}" > /etc/prof-results/run-stats.json \
  || echo "WARNING: could not write run-stats.json"

echo "INFO: running callgrind_annotate to generate report"
callgrind_annotate \
  $(find /etc/prof-results -name "callgrind.out.*" -size +0c | sort) \
  > /etc/prof-results/callgrind_report.txt

# Restore stdout/stderr
exec > /dev/null 2>&1
