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
echo "TEST_LOADGEN_NUM_MESSAGES=$TEST_LOADGEN_NUM_MESSAGES"
echo ""

# Approximate load-generator send duration; the instrumented run sleeps this
# long between callgrind_control --instr=on and the graceful shutdown signal.
SEND_DURATION=$(( TEST_LOADGEN_NUM_MESSAGES / TEST_LOADGEN_START_PPS ))

# Start freeradius under valgrind with instrumentation off.
#
# valgrind writes its own log to --log-file and freeradius stdout/stderr
# go directly to freeradius.log. Avoiding `| tee` here so $! is the
# valgrind PID rather than tee's — the fallback kill paths below rely on it.
valgrind \
  --tool=callgrind \
  --log-file=/etc/prof-results/valgrind.log \
  --callgrind-out-file=/etc/prof-results/callgrind.out.%p \
  --trace-children=yes \
  --separate-threads=no \
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

# Wait for valgrind to finish writing callgrind output
echo "INFO: waiting for valgrind to exit"
wait ${VALGRIND_PID} 2>/dev/null || true

# Signal that valgrind has finished writing all profiling data
echo "INFO: Profiling complete at $(date)"

echo "INFO: running callgrind_annotate to generate report"
callgrind_annotate \
  $(find /etc/prof-results -name "callgrind.out.*" -size +0c | sort) \
  > /etc/prof-results/callgrind_report.txt

# Restore stdout/stderr
exec > /dev/null 2>&1
