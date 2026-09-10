#!/bin/bash
#
#  gperftools profiling script for the multi-server profiling tests.
#
#  This script start and stops gperftools profiling using the SIGUSR2 signal
#  since it is an available signal. SIGUSR2 = 12.
#
#  Results, all under /etc/prof-results:
#    gperftools_profiling.log             this script's log
#    freeradius_gperftools.log            server stdout/stderr
#    freeradius_gperftools.prof.<pid>.<n> raw gperftools dump, one per on/off cycle
#    pprof.out.<pid>.pb.gz                merged profile, symbols resolved
#    pprof_report.txt                     pprof -text report, for reading by hand
#    gperftools-exit-status               gperftools or pprof status
#
set -u

# Common functions
source "${0%/*}/common_profiling.sh"

RESULTS=/etc/prof-results

# gperftools profiling variables
GPERFTOOLS_CPUPROFILE="$RESULTS/freeradius_gperftools.prof.$$"
GPERFTOOLS_CPUPROFILESIGNAL=12
GPERFTOOLS_CPUPROFILE_FREQUENCY=1000

# Clean up previous files if they exist from a previous run
rm -f "$RESULTS"/gperftools_profiling.log \
      "$RESULTS"/freeradius_gperftools.log \
      "$RESULTS"/freeradius_gperftools.prof.* \
      "$RESULTS"/pprof.out.* \
      "$RESULTS"/pprof_report.txt \
      "$RESULTS"/gperftools-exit-status

# All scripts errors and logs redirected to log file
exec > "$RESULTS/gperftools_profiling.log" 2>&1

#  STATUS:
#    0  gperftools profiling successful
#    2  gperftools profiling not successful
#    3  pprof issue detected
STATUS=2
log_status

#  LOAD_TIMEOUT bounds the load phase. The bound is the time to send every
#  request at start_pps plus a margin for replies not yet received. The
#  completion line normally arrives at the send time of the ramp.
LOAD_TIMEOUT=$(( TEST_LOADGEN_MAX_REQUESTS / TEST_LOADGEN_START_PPS + 60 ))

# Start server using its PID
cd "$RESULTS" || { echo "ERROR: cannot cd to $RESULTS"; log_status; }
bash -c 'exec env \
  CPUPROFILE=$GPERFTOOLS_CPUPROFILE \
  CPUPROFILESIGNAL=$GPERFTOOLS_CPUPROFILESIGNAL \
  CPUPROFILE_FREQUENCY=$GPERFTOOLS_CPUPROFILE_FREQUENCY \
  freeradius -s -l stdout -S resources.talloc_skip_cleanup=yes' \
  > "$RESULTS/freeradius_gperftools.log" 2>&1 &
FR_PID=$!
echo "INFO: freeradius started, pid ${FR_PID}"

# Wait for the server to be ready. Timeout is long by design since the server is expected
# to startup
STARTUP_TIMEOUT=120
STARTUP_ELAPSED=0
until grep -q "Ready to process requests" "$RESULTS/freeradius_gperftools.log"; do
  sleep 1
  STARTUP_ELAPSED=$(( STARTUP_ELAPSED + 1 ))
  if [ ${STARTUP_ELAPSED} -ge ${STARTUP_TIMEOUT} ]; then
    echo "ERROR: freeradius still not ready to process requests after ${STARTUP_TIMEOUT} seconds, aborting"
    kill -SIGKILL ${FR_PID} 2>/dev/null
    log_status
    exit 1
  fi
done
echo "INFO: freeradius ready after ${STARTUP_ELAPSED}s"

#  Start gperftools profiling
echo "INFO: starting gperftools profiling"
kill -SIGUSR2 "$FR_PID"

#  Wait for proto_load to report completion. proto_load logs the completion
#  line only after sending every request and receiving every reply, so the
#  counts on the completion line are the totals of the run.
LOAD_ELAPSED=0
until grep -q "Load test for .* complete - sent" "$RESULTS/freeradius_gperftools.log"; do
  if ! kill -0 "$FR_PID" 2>/dev/null; then
    wait "$FR_PID"
    STATUS=$?
    echo "ERROR: freeradius exited with status $STATUS during the load phase, see freeradius_gperftools.log"
    log_status
  fi

  sleep 1

  LOAD_ELAPSED=$(( LOAD_ELAPSED + 1 ))
  if [ "$LOAD_ELAPSED" -ge "$LOAD_TIMEOUT" ]; then
    echo "ERROR: killing freeradius, proto_load did not report completion within ${LOAD_TIMEOUT}s. Capture is partial and will not be published"
    kill -SIGKILL "$FR_PID" 2>/dev/null
    log_status
  fi
done
grep "Load test for .* complete - sent" "$RESULTS/freeradius_gperftools.log"
echo "INFO: load complete after ${LOAD_ELAPSED}s (max_requests ${TEST_LOADGEN_MAX_REQUESTS})"

#  Stop gperftools profiling
echo "INFO: stopping gperftools profiling"
kill -SIGUSR2 "$FR_PID"

shutdown_freeradius

# Graceful shutdown of freeradius process (equivalent to Ctrl+C)
#echo "INFO: sending SIGINT to freeradius ${FR_PID} for graceful shutdown"
#kill -SIGINT "$FR_PID"

#SHUTDOWN_TIMEOUT=60
#SHUTDOWN_ELAPSED=0
#while kill -0 "$FR_PID" 2>/dev/null; do
#  sleep 1
#  SHUTDOWN_ELAPSED=$(( SHUTDOWN_ELAPSED + 1 ))
#  if [ "$SHUTDOWN_ELAPSED" -ge "$SHUTDOWN_TIMEOUT" ]; then
#    echo "WARNING: sending SIGKILL, freeradius did not exit within ${SHUTDOWN_TIMEOUT}s after SIGINT"
#    kill -SIGKILL "$FR_PID" 2>/dev/null
#    break
#  fi
#done

#FR_STATUS=0
#wait "$FR_PID" 2>/dev/null || FR_STATUS=$?
#echo "INFO: freeradius exited with status ${FR_STATUS} after ${SHUTDOWN_ELAPSED}s"

if [ "$FR_STATUS" -ne 0 ]; then
  if [ "$FR_STATUS" -gt 128 ]; then
    echo "ERROR: signal $((FR_STATUS - 128)) killed freeradius during shutdown, see freeradius_gperftools.log"
  else
    echo "ERROR: freeradius exited ${FR_STATUS} during shutdown, see freeradius_gperftools.log"
  fi
  echo "ERROR: these results will not be published"
fi

if ! ls "$RESULTS"/freeradius_gperftools.prof."$FR_PID".* >/dev/null 2>&1; then
  echo "ERROR: exiting, gperftools did not write a profile dump"
  STATUS=2
  log_status
fi

#  Convert in the container while the build that the addresses belong to still
#  exists. pprof takes the main binary as the first argument. pprof finds the
#  shared objects through the mappings recorded in the dump, and falls back to
#  PPROF_BINARY_PATH (libfreeradius-*.so and rlm_*.so both install into
#  /usr/lib).
if ! command -v pprof >/dev/null 2>&1; then
  echo "ERROR: keeping raw dumps only, pprof is not installed in this image. No pprof.out.*.pb.gz or pprof_report.txt"
  STATUS=3
  log_status
fi
export PPROF_BINARY_PATH=/usr/lib
RADIUSD_BIN=$(readlink -f "$(command -v freeradius)")

echo "INFO: merging dumps into pprof.out.${FR_PID}.pb.gz"
if ! pprof -proto "$RADIUSD_BIN" "$RESULTS"/freeradius_gperftools.prof."$FR_PID".* > "$RESULTS/pprof.out.${FR_PID}.pb.gz"; then
  echo "ERROR: pprof -proto failed"
  rm -f "$RESULTS/pprof.out.${FR_PID}.pb.gz"
  STATUS=3
  log_status
fi

#  -nodefraction=0 keeps every function in the table, for parity with
#  callgrind_report.txt, which lists every function. The default drops rows
#  under 0.5% of the total.
echo "INFO: writing pprof_report.txt"
if ! pprof -text -nodefraction=0 "$RADIUSD_BIN" "$RESULTS"/freeradius_gperftools.prof."$FR_PID".* > "$RESULTS/pprof_report.txt"; then
  echo "ERROR: pprof -text failed"
  STATUS=3
  log_status
fi
head -6 "$RESULTS/pprof_report.txt"

#  A report without a FreeRADIUS symbol means that symbolization failed, and
#  the reader cannot attribute the numbers in the report to any function.
if ! grep -qE '\b(fr_|unlang_|main\b)' "$RESULTS/pprof_report.txt"; then
  echo "ERROR: pprof did not resolve any FreeRADIUS function name in pprof_report.txt"
  STATUS=3
  log_status
fi

STATUS=$FR_STATUS
log_status
