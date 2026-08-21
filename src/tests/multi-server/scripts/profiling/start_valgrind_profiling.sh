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
if [ -z "${FR_PID}" ]; then
  echo "WARNING: could not determine freeradius PID from callgrind_control output, sending SIGINT to valgrind instead"
  kill -SIGINT ${VALGRIND_PID} 2>/dev/null || true
else
  echo "INFO: killing freeradius process ${FR_PID} with SIGINT for graceful shutdown"
  kill -SIGINT ${FR_PID}

  # Wait for freeradius to finish its graceful shutdown before stopping instrumentation
  SHUTDOWN_TIMEOUT=60
  SHUTDOWN_ELAPSED=0
  while kill -0 "${FR_PID}" 2>/dev/null; do
    sleep 1
    SHUTDOWN_ELAPSED=$(( SHUTDOWN_ELAPSED + 1 ))
    if [ ${SHUTDOWN_ELAPSED} -ge ${SHUTDOWN_TIMEOUT} ]; then
      echo "WARNING: freeradius did not exit within ${SHUTDOWN_TIMEOUT}s after SIGINT"
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
  #  Over 128 means a signal. Valgrind passes the profiled server's exit
  #  status through (verified: freeradius's own _EXIT(134) matched the 134
  #  recorded here on the e26e348 ldap run), so a signal status usually
  #  means FREERADIUS died of that signal - an assert or crash logged in
  #  freeradius.log - rather than valgrind itself being killed.
  #  valgrind.log's "brk segment overflow" warning is NOT the reason: clean
  #  runs carry it too (glibc falls back to mmap when brk cannot grow).
  if [ "${VALGRIND_STATUS}" -gt 128 ]; then
    SIG=$((VALGRIND_STATUS - 128))
    case ${SIG} in
    6)  SIGNAME="SIGABRT (abort/assertion)" ;;
    9)  SIGNAME="SIGKILL (OOM killer or forced teardown)" ;;
    11) SIGNAME="SIGSEGV (crash)" ;;
    15) SIGNAME="SIGTERM" ;;
    *)  SIGNAME="signal ${SIG}" ;;
    esac
    echo "ERROR: exit status ${VALGRIND_STATUS}: ${SIGNAME}; freeradius likely died of that signal (see freeradius.log for asserts/backtraces)" >&2
  else
    echo "ERROR: valgrind exited ${VALGRIND_STATUS}; profiling data may be truncated" >&2
  fi
  echo "ERROR: these results will not be published" >&2
fi

# Signal that valgrind has finished writing all profiling data
echo "INFO: Profiling complete at $(date)"

echo "INFO: running callgrind_annotate to generate report"
callgrind_annotate \
  $(find /etc/prof-results -name "callgrind.out.*" -size +0c | sort) \
  > /etc/prof-results/callgrind_report.txt

# Restore stdout/stderr
exec > /dev/null 2>&1
