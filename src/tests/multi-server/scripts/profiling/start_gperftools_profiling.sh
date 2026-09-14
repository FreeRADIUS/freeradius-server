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

# Clean up previous files if they exist from a previous run
rm -f "$RESULTS"/gperftools_profiling.log \
      "$RESULTS"/freeradius_gperftools.log \
      "$RESULTS"/freeradius_gperftools.prof.* \
      "$RESULTS"/pprof.out.* \
      "$RESULTS"/pprof_report.txt \
      "$RESULTS"/gperftools-exit-status

# All scripts errors and logs redirected to log file
exec > "$RESULTS/gperftools_profiling.log" 2>&1

# Script status exit code
#
# STATUS:
#   0  profiling successful
#   2  profiling not successful
#   3  pprof issue detected

# Default status
STATUS=2

# Set PROTO_LOAD_TIMEOUT based on max requests and the packet rate
PROTO_LOAD_TIMEOUT=$(( TEST_LOADGEN_MAX_REQUESTS / TEST_LOADGEN_START_PPS + 60 ))

# Override the default test config which sets on_complete to "exit" which shuts
# down the server and unloads the modules.  With gperftools and pprof,
# we must make sure the profile is closed while the modules are still mapped.
export TEST_LOADGEN_COMPLETE=stop

echo "Profiling with load-generator configuration:"
env | grep '^TEST_LOADGEN_' | sort | sed 's/^/  /'

# Start server using its PID to make it easier to manage process shutdown
cd "$RESULTS" || { echo "ERROR: cannot cd to $RESULTS"; log_status_and_exit; }
bash -c 'exec env \
  CPUPROFILE="/etc/prof-results/freeradius_gperftools.prof.$$" \
  CPUPROFILESIGNAL=12 \
  CPUPROFILE_FREQUENCY=1000 \
  freeradius -s -l stdout -S resources.talloc_skip_cleanup=yes' \
  > "$RESULTS/freeradius_gperftools.log" 2>&1 &
FR_PID=$!
echo "INFO: freeradius started, pid ${FR_PID}"

# Wait for the server to be ready.  "Ready to process requests" ensures that the
# server has completed its startup sequence.
STARTUP_TIMEOUT=120
STARTUP_ELAPSED=0
until grep -q "Ready to process requests" "$RESULTS/freeradius_gperftools.log"; do
  sleep 1
  STARTUP_ELAPSED=$(( STARTUP_ELAPSED + 1 ))
  if [ ${STARTUP_ELAPSED} -ge ${STARTUP_TIMEOUT} ]; then
    echo "ERROR: freeradius still not ready to process requests after ${STARTUP_TIMEOUT} seconds, aborting"
    kill -SIGKILL ${FR_PID} 2>/dev/null
    log_status_and_exit
    exit 1
  fi
done
echo "INFO: freeradius ready after ${STARTUP_ELAPSED}s"

# Start gperftools profiling
echo "INFO: starting gperftools profiling"
kill -SIGUSR2 "$FR_PID"

# Wait for proto_load to indicate that it has finished sending all requests.
PROTO_LOAD_ELAPSED_TIME=0
while kill -0 "$FR_PID" 2>/dev/null; do
  if grep -q "Load test for .* complete - sent" "$RESULTS/freeradius_gperftools.log"; then
    echo "INFO: proto_load successfully sent all requests"
    break
  fi
  # Sleep to ensure loop doesn't consume too much of the CPU cycles
  sleep 2

  PROTO_LOAD_ELAPSED_TIME=$(( PROTO_LOAD_ELAPSED_TIME + 2 ))
  if [ "$PROTO_LOAD_ELAPSED_TIME" -ge "$PROTO_LOAD_TIMEOUT" ]; then
    echo "ERROR: killing freeradius, proto_load did not report completion within ${PROTO_LOAD_TIMEOUT}s. Capture is partial and will not be published"
    kill -SIGKILL "$FR_PID" 2>/dev/null
    log_status_and_exit
  fi
done

# Stop gperftools profiling
echo "INFO: stopping gperftools profiling"
kill -SIGUSR2 "$FR_PID"

shutdown_freeradius

# Check if gperftools generated a profile dump
if ! ls "$RESULTS"/freeradius_gperftools.prof."$FR_PID".* >/dev/null 2>&1; then
  echo "ERROR: exiting, gperftools did not write a profile dump"
  STATUS=2
  log_status_and_exit
fi

# Check if pprof is installed
# pprof finds the shared objects through the mappings recorded in the dump,
# and falls back to PPROF_BINARY_PATH.
#
# libfreeradius-*.so and rlm_*.so both install into /usr/lib.
export PPROF_BINARY_PATH=/usr/lib
if ! command -v pprof >/dev/null 2>&1; then
  echo "ERROR: pprof is not installed in this image, no pprof* files generated"
  STATUS=3
  log_status_and_exit
fi

# Find path to radiusd required by pprof command
RADIUSD_BIN=$(readlink -f "$(command -v freeradius)")

# Compress gperftools results
echo "INFO: Compressing gperftools results into pprof.out.${FR_PID}.pb.gz"
if ! pprof -proto "$RADIUSD_BIN" "$RESULTS"/freeradius_gperftools.prof."$FR_PID".* > "$RESULTS/pprof.out.${FR_PID}.pb.gz"; then
  echo "ERROR: pprof -proto failed"
  rm -f "$RESULTS/pprof.out.${FR_PID}.pb.gz"
  STATUS=3
  log_status_and_exit
fi

# Generate pprof text report based off of gperftools results
# Using -nodefraction=0 to ensure all nodes are included
echo "INFO: writing pprof_report.txt"
if ! pprof -text -nodefraction=0 "$RADIUSD_BIN" "$RESULTS"/freeradius_gperftools.prof."$FR_PID".* > "$RESULTS/pprof_report.txt"; then
  echo "ERROR: pprof -text failed"
  STATUS=3
  log_status_and_exit
fi
head -6 "$RESULTS/pprof_report.txt"

# If we've reached this point, profiling has been successful
STATUS=0
log_status_and_exit
