#!/bin/bash

# To be run inside the profiling container

# Clear any stale marker from a previous run
rm -f /etc/prof-results/.profiling_complete
rm -f /etc/prof-results/valgrind_profiling.log

exec > /etc/prof-results/valgrind_profiling.log 2>&1

# Ignore SIGTERM — freeradius broadcasts it to the process group on shutdown,
# which would otherwise kill this script before it can touch .profiling_complete
trap '' SIGTERM

# Load proto_load config to get packet settings
source /etc/freeradius/proto_load_config.env

# Calculate approximate send duration
SEND_DURATION=$(( TEST_LOADGEN_NUM_MESSAGES / TEST_LOADGEN_START_PPS ))
PROFILE_DURATION_BUFFER=15
PROFILE_DURATION=$SEND_DURATION-$PROFILE_DURATION_BUFFER

# Start freeradius under valgrind with instrumentation off
valgrind \
  --tool=callgrind \
  --callgrind-out-file=/etc/prof-results/callgrind.out.%p \
  --trace-children=yes \
  --separate-threads=yes \
  --dump-instr=yes \
  --collect-jumps=yes \
  --cache-sim=yes \
  --branch-sim=yes \
  --keep-debuginfo=yes \
  --instr-atstart=no \
  freeradius -f -l stdout -S resources.talloc_skip_cleanup=yes 2>&1 | \
  tee /etc/prof-results/freeradius.log &
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

# Stop instrumentation before shutdown so valgrind only flushes already-collected data
echo "INFO: disabling callgrind instrumentation"
CTRL_OUT=$(callgrind_control --instr=off 2>/dev/null || true)
printf '%s\n' "$CTRL_OUT"

# Graceful shutdown (equivalent to Ctrl+C)
if [ -z "${FR_PID}" ]; then
  echo "WARNING: could not determine freeradius PID from callgrind_control output, sending SIGINT to valgrind pipeline instead"
  kill -SIGINT ${VALGRIND_PID} 2>/dev/null || true
else
  echo "INFO: killing freeradius process ${FR_PID} with SIGINT for graceful shutdown"
  kill -SIGINT ${FR_PID}
fi

# Give valgrind time to write callgrind output after freeradius exits
echo "INFO: sleeping for 5s"
sleep 5

# Signal that valgrind has finished writing all profiling data
echo "INFO: Profiling complete at $(date)"

echo "INFO: running callgrind_annotate to generate report"
#callgrind_annotate $(find /etc/prof-results -name "callgrind.out.*" -size +0c | sort) > /etc/prof-results/callgrind_report.txt
cmd='callgrind_annotate $(find /etc/prof-results -name "callgrind.out.*" -size +0c | sort) > /etc/prof-results/callgrind_report.txt'
echo "$cmd"
eval "$cmd"

# Restore stdout/stderr
exec > /dev/null 2>&1
