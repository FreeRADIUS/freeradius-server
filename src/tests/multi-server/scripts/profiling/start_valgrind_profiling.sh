#!/bin/bash

# Common functions
source "${0%/*}/common_profiling.sh"

RESULTS=/etc/prof-results

# Valgrind profiling script to be run inside the profiling container

# Clear any stale marker from a previous run
rm -f "$RESULTS/.profiling_complete"
rm -f "$RESULTS/valgrind_profiling.log"
rm -f "$RESULTS/freeradius_valgrind.log"

exec > "$RESULTS/valgrind_profiling.log" 2>&1

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
# valgrind logs to --log-file
# freeradius stdout/stderr logs to freeradius_valgrind.log
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
  --log-file="$RESULTS/valgrind.log" \
  --callgrind-out-file="$RESULTS/callgrind.out.%p" \
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
  > "$RESULTS/freeradius_valgrind.log" 2>&1 &
VALGRIND_PID=$!

# Wait for the server to be ready. Timeout is long by design since the server is expected
# to startup
STARTUP_TIMEOUT=300
STARTUP_ELAPSED=0
until grep -q "Ready to process requests" "$RESULTS/freeradius_valgrind.log"; do
  sleep 1
  STARTUP_ELAPSED=$(( STARTUP_ELAPSED + 1 ))
  if [ ${STARTUP_ELAPSED} -ge ${STARTUP_TIMEOUT} ]; then
    echo "ERROR: freeradius still not ready to process requests after ${STARTUP_TIMEOUT} seconds, aborting"
    kill -SIGKILL ${VALGRIND_PID} 2>/dev/null
    log_status
    exit 1
  fi
done
echo "INFO: freeradius ready after ${STARTUP_ELAPSED}s"

# Start callgrind and get freeradius process PID to ensure a proper shutdown
echo "INFO: enabling callgrind instrumentation"
CTRL_OUT=$(callgrind_control --instr=on)
printf '%s\n' "$CTRL_OUT"
FR_PID=$(printf '%s\n' "$CTRL_OUT" | grep -oP 'PID \K\d+(?=: freeradius)' | head -1)
echo "Freeradius PID: ${FR_PID}"

# Wait for the approximate duration of the test to ensure proto_load
# has sent all of its packets
sleep ${SEND_DURATION}

# Shutdown server
shutdown_freeradius

# Stop callgrind after freeradius has stopped
echo "INFO: disabling callgrind instrumentation"
CTRL_OUT=$(callgrind_control --instr=off 2>/dev/null || true)
printf '%s\n' "$CTRL_OUT"

# Save valgrind exit status that allows us to check if we have
# partial profiling results from the run.
# 0:        clean run
# non-zero: valgrind exited with an error
#
echo "INFO: waiting for valgrind to exit"
STATUS=0
wait ${VALGRIND_PID} 2>/dev/null || STATUS=$?

# Write status to file
log_status

if [ "${STATUS}" -ne 0 ]; then
    # >128: killed by signal (128 + signal number)
    #  139: SIGSEGV. not a real crash; see valgrind.log above its backtrace.
    if [ "${STATUS}" -gt 128 ]; then
        echo "ERROR: valgrind was killed by signal $((STATUS - 128)); profiling data is truncated" >&2
    else
        echo "ERROR: valgrind exited ${STATUS}; profiling data may be truncated" >&2
    fi
    echo "ERROR: see valgrind.log for the reason; these results will not be published" >&2
fi

# Signal that valgrind has finished writing all profiling data
echo "INFO: Profiling complete at $(date)"

echo "INFO: running callgrind_annotate to generate report"
callgrind_annotate \
  $(find "$RESULTS" -name "callgrind.out.*" -size +0c | sort) \
  > "$RESULTS/callgrind_report.txt"

# Restore stdout/stderr
exec > /dev/null 2>&1
