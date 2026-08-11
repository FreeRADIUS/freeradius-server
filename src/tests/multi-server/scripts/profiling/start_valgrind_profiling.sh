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

# Dump the load-phase profile while the server is still healthy. The dump
# lands in callgrind.out.<pid>.1 and resets the counters, so the termination
# dump holds only the shutdown phase and the parts sum to the old single-dump
# totals. If shutdown hangs, the data is already safe on disk.
echo "INFO: dumping load-phase profile before shutdown"
DUMP_OK=0
if callgrind_control --dump > /dev/null 2>&1; then
  DUMP_OK=1
else
  echo "WARNING: pre-shutdown dump failed; a shutdown hang will lose this run"
fi

# Graceful shutdown (equivalent to Ctrl+C) — keep instrumentation on so shutdown
# transitions are captured (in the post-dump part) before we stop profiling
if [ -z "${FR_PID}" ]; then
  echo "WARNING: could not determine freeradius PID from callgrind_control output, sending SIGINT to valgrind instead"
  FR_PID=${VALGRIND_PID}
fi
echo "INFO: killing freeradius process ${FR_PID} with SIGINT for graceful shutdown"
kill -SIGINT ${FR_PID}

# Wait for graceful shutdown; SIGKILL a hung one. The dump above already
# holds the data, and hanging until the framework timeout would leave no
# exit status at all. 20s is 10x the longest clean shutdown observed;
# observed hangs never resolve, and a short wait preserves verify-timeout
# budget for callgrind_annotate below.
SHUTDOWN_TIMEOUT=20
SHUTDOWN_ELAPSED=0
SHUTDOWN_HUNG=0
while kill -0 "${FR_PID}" 2>/dev/null; do
  sleep 1
  SHUTDOWN_ELAPSED=$(( SHUTDOWN_ELAPSED + 1 ))
  if [ ${SHUTDOWN_ELAPSED} -ge ${SHUTDOWN_TIMEOUT} ]; then
    SHUTDOWN_HUNG=1
    echo "WARNING: freeradius did not exit within ${SHUTDOWN_TIMEOUT}s after SIGINT; sending SIGKILL"
    kill -SIGKILL ${VALGRIND_PID} 2>/dev/null || true
    break
  fi
done
echo "INFO: freeradius exited after ${SHUTDOWN_ELAPSED}s"

# Stop instrumentation after graceful shutdown so all shutdown transitions are captured
echo "INFO: disabling callgrind instrumentation"
CTRL_OUT=$(callgrind_control --instr=off 2>/dev/null || true)
printf '%s\n' "$CTRL_OUT"

# Record whether the profiling data is trustworthy in valgrind-exit-status:
# the publish step refuses to upload a non-zero run, and an absent file means
# "the wrapper did not get this far". One exception: a shutdown hang ended by
# our own SIGKILL above still has complete load-phase data, so the status
# stays 0 and the hang is recorded in shutdown-status instead ("clean" /
# "timeout-sigkill", written on every run).
echo "INFO: waiting for valgrind to exit"
VALGRIND_STATUS=0
wait ${VALGRIND_PID} 2>/dev/null || VALGRIND_STATUS=$?

SHUTDOWN_OUTCOME=clean
if [ "${VALGRIND_STATUS}" -ne 0 ] && [ "${SHUTDOWN_HUNG}" -eq 1 ] && [ "${DUMP_OK}" -eq 1 ]; then
  SHUTDOWN_OUTCOME=timeout-sigkill
  echo "WARNING: shutdown hang ended by SIGKILL; load-phase data was dumped beforehand and is intact"
  VALGRIND_STATUS=0
  # No termination dump happened; remove the empty base callgrind.out stub.
  find /etc/prof-results -name "callgrind.out.*" -size 0c -delete
fi
echo "${VALGRIND_STATUS}" > /etc/prof-results/valgrind-exit-status
echo "${SHUTDOWN_OUTCOME}" > /etc/prof-results/shutdown-status

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

# One report section per data file: callgrind_annotate reads profile data
# only from its FIRST argument (the old multi-file call reported just
# whichever file sorted first). stderr stays inline so failures are visible.
echo "INFO: running callgrind_annotate to generate report"
{
  for f in $(find /etc/prof-results -name "callgrind.out.*" -size +0c | sort); do
    echo "================================================================"
    echo "==== ${f}"
    echo "================================================================"
    callgrind_annotate "${f}" 2>&1 || true
    echo ""
  done
} > /etc/prof-results/callgrind_report.txt

# Restore stdout/stderr
exec > /dev/null 2>&1
