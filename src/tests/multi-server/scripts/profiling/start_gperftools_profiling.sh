#!/bin/bash
#
#  gperftools profiling script for the multi-server profiling tests.
#
#  This script turns sampling on using SIGUSR2 and CPUPROFILESIGNAL when the server
#  is ready and turns it off when proto_load has finished sending packets.
#
#  Server startup and shutdown are not profiled with --instr-atstart=no
#
#  Results, all under /etc/prof-results:
#    gperftools_profiling.log             this script's log
#    freeradius_gperftools.log            server stdout/stderr
#    freeradius_gperftools.prof.<pid>.<n> raw gperftools dump, one per on/off cycle
#    pprof.out.<pid>.pb.gz                merged profile, symbols resolved
#    pprof_report.txt                     pprof -text report, for reading by hand
#    gperftools-exit-status               0 for a complete, converted capture.
#                                         2 load did not complete or no profile dump
#                                         3 pprof missing, failed, or no symbols
#
set -u

RESULTS=/etc/prof-results

rm -f "$RESULTS"/gperftools_profiling.log "$RESULTS"/freeradius_gperftools.log \
      "$RESULTS"/freeradius_gperftools.prof.* "$RESULTS"/pprof.out.* \
      "$RESULTS"/pprof_report.txt "$RESULTS"/gperftools-exit-status

exec > "$RESULTS/gperftools_profiling.log" 2>&1

#  finish() writes the status file on every exit path, so an absent file means
#  that the script exited before reaching finish, not that the run passed.
STATUS=2
finish() {
  echo "$STATUS" > "$RESULTS/gperftools-exit-status"
  echo "INFO: gperftools capture finished at $(date) with status $STATUS"
  exit "$STATUS"
}

echo "proto_load configuration environment variables:"
env | grep '^TEST_LOADGEN_' | sort
echo ""

#  This script closes the profile before shutdown, so the server must outlive
#  the load. With on_complete=exit, proto_load stops the server the moment the
#  load completes, and the shutdown races the SIGUSR2 that closes the profile.
if [ "${TEST_LOADGEN_COMPLETE:-}" != "stop" ]; then
  echo "INFO: overriding on_complete '${TEST_LOADGEN_COMPLETE:-}' with 'stop', this script closes the profile before shutting the server down"
  export TEST_LOADGEN_COMPLETE=stop
fi

#  LOAD_TIMEOUT bounds the load phase. The bound is the time to send every
#  request at start_pps plus a margin for replies not yet received. The
#  completion line normally arrives at the send time of the ramp.
LOAD_TIMEOUT=$(( TEST_LOADGEN_MAX_REQUESTS / TEST_LOADGEN_START_PPS + 60 ))

#  Start the server with the profiler loaded but not sampling.
#
#  CPUPROFILE            dump path. gperftools appends .<n> per on/off cycle.
#                        <pid> is the server's own pid, matching callgrind.out.<pid>:
#                        the inner bash expands $$ to its pid and exec's the
#                        server without forking, so both share that pid.
#  CPUPROFILESIGNAL      sampling starts and stops on this signal, and does
#                        not start at launch (12 = SIGUSR2, which radiusd does
#                        not handle)
#  CPUPROFILE_FREQUENCY  samples per CPU-second. A 6000-packet run costs well
#                        under a second of CPU, so the 100 Hz default would
#                        leave tens of samples for the whole profile.
#
#  The command does not pipe through tee, because $! must be the server pid
#  and the readiness and completion checks read the log file.

cd "$RESULTS" || { echo "ERROR: cannot cd to $RESULTS"; finish; }
bash -c 'exec env \
  CPUPROFILE="/etc/prof-results/freeradius_gperftools.prof.$$" \
  CPUPROFILESIGNAL=12 \
  CPUPROFILE_FREQUENCY=1000 \
  freeradius -s -l stdout -S resources.talloc_skip_cleanup=yes' \
  > "$RESULTS/freeradius_gperftools.log" 2>&1 &
FR_PID=$!
echo "INFO: freeradius started, pid ${FR_PID}"

#  Wait for the server to report ready. Exit if the server exits first.
STARTUP_TIMEOUT=120
STARTUP_ELAPSED=0
until grep -q "Ready to process requests" "$RESULTS/freeradius_gperftools.log"; do
  if ! kill -0 "$FR_PID" 2>/dev/null; then
    wait "$FR_PID"; STATUS=$?
    echo "ERROR: freeradius exited with status $STATUS before becoming ready, see freeradius_gperftools.log"
    finish
  fi
  sleep 1
  STARTUP_ELAPSED=$(( STARTUP_ELAPSED + 1 ))
  if [ "$STARTUP_ELAPSED" -ge "$STARTUP_TIMEOUT" ]; then
    echo "ERROR: aborting, freeradius did not become ready within ${STARTUP_TIMEOUT}s"
    kill -SIGKILL "$FR_PID" 2>/dev/null
    finish
  fi
done
echo "INFO: freeradius ready after ${STARTUP_ELAPSED}s"

#  Turn sampling on.
echo "INFO: enabling gperftools sampling (SIGUSR2)"
kill -SIGUSR2 "$FR_PID"

#  Wait for proto_load to report completion. With on_complete=stop, proto_load
#  logs the completion line only after sending every request and receiving
#  every reply, so the counts on the completion line are the totals of the run.
LOAD_ELAPSED=0
until grep -q "Load test for .* complete - sent" "$RESULTS/freeradius_gperftools.log"; do
  if ! kill -0 "$FR_PID" 2>/dev/null; then
    wait "$FR_PID"; STATUS=$?
    echo "ERROR: freeradius exited with status $STATUS during the load phase, see freeradius_gperftools.log"
    finish
  fi
  sleep 1
  LOAD_ELAPSED=$(( LOAD_ELAPSED + 1 ))
  if [ "$LOAD_ELAPSED" -ge "$LOAD_TIMEOUT" ]; then
    echo "ERROR: killing freeradius, proto_load did not report completion within ${LOAD_TIMEOUT}s. Capture is partial and will not be published"
    kill -SIGKILL "$FR_PID" 2>/dev/null
    finish
  fi
done
grep "Load test for .* complete - sent" "$RESULTS/freeradius_gperftools.log"
echo "INFO: load complete after ${LOAD_ELAPSED}s (max_requests ${TEST_LOADGEN_MAX_REQUESTS})"

#  Turn sampling off. gperftools writes the dump from the signal handler, so
#  the file appears as soon as the server handles the signal.
echo "INFO: disabling gperftools sampling (SIGUSR2)"
kill -SIGUSR2 "$FR_PID"
DUMP_WAIT=0
until ls "$RESULTS"/freeradius_gperftools.prof."$FR_PID".* >/dev/null 2>&1; do
  sleep 1
  DUMP_WAIT=$(( DUMP_WAIT + 1 ))
  if [ "$DUMP_WAIT" -ge 30 ]; then
    echo "ERROR: continuing without a profile dump, none appeared within ${DUMP_WAIT}s of stopping the profiler"
    break
  fi
done
ls -l "$RESULTS"/freeradius_gperftools.prof."$FR_PID".* 2>/dev/null

#  Shut the server down gracefully with SIGINT (equivalent to Ctrl+C). The
#  profile is already on disk, so a hang during shutdown costs the run a
#  clean exit status but not the profile.
echo "INFO: sending SIGINT to freeradius ${FR_PID} for graceful shutdown"
kill -SIGINT "$FR_PID"
SHUTDOWN_TIMEOUT=60
SHUTDOWN_ELAPSED=0
while kill -0 "$FR_PID" 2>/dev/null; do
  sleep 1
  SHUTDOWN_ELAPSED=$(( SHUTDOWN_ELAPSED + 1 ))
  if [ "$SHUTDOWN_ELAPSED" -ge "$SHUTDOWN_TIMEOUT" ]; then
    echo "WARNING: sending SIGKILL, freeradius did not exit within ${SHUTDOWN_TIMEOUT}s after SIGINT"
    kill -SIGKILL "$FR_PID" 2>/dev/null
    break
  fi
done
FR_STATUS=0
wait "$FR_PID" 2>/dev/null || FR_STATUS=$?
echo "INFO: freeradius exited with status ${FR_STATUS} after ${SHUTDOWN_ELAPSED}s"

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
  finish
fi

#  Convert in the container while the build that the addresses belong to still
#  exists. pprof takes the main binary as the first argument. pprof finds the
#  shared objects through the mappings recorded in the dump, and falls back to
#  PPROF_BINARY_PATH (libfreeradius-*.so and rlm_*.so both install into
#  /usr/lib).
if ! command -v pprof >/dev/null 2>&1; then
  echo "ERROR: keeping raw dumps only, pprof is not installed in this image. No pprof.out.*.pb.gz or pprof_report.txt"
  STATUS=3
  finish
fi
export PPROF_BINARY_PATH=/usr/lib
RADIUSD_BIN=$(readlink -f "$(command -v freeradius)")

echo "INFO: merging dumps into pprof.out.${FR_PID}.pb.gz"
if ! pprof -proto "$RADIUSD_BIN" "$RESULTS"/freeradius_gperftools.prof."$FR_PID".* > "$RESULTS/pprof.out.${FR_PID}.pb.gz"; then
  echo "ERROR: pprof -proto failed"
  rm -f "$RESULTS/pprof.out.${FR_PID}.pb.gz"
  STATUS=3
  finish
fi

#  -nodefraction=0 keeps every function in the table, for parity with
#  callgrind_report.txt, which lists every function. The default drops rows
#  under 0.5% of the total.
echo "INFO: writing pprof_report.txt"
if ! pprof -text -nodefraction=0 "$RADIUSD_BIN" "$RESULTS"/freeradius_gperftools.prof."$FR_PID".* > "$RESULTS/pprof_report.txt"; then
  echo "ERROR: pprof -text failed"
  STATUS=3
  finish
fi
head -6 "$RESULTS/pprof_report.txt"

#  A report without a FreeRADIUS symbol means that symbolization failed, and
#  the reader cannot attribute the numbers in the report to any function.
if ! grep -qE '\b(fr_|unlang_|main\b)' "$RESULTS/pprof_report.txt"; then
  echo "ERROR: pprof did not resolve any FreeRADIUS function name in pprof_report.txt"
  STATUS=3
  finish
fi

STATUS=$FR_STATUS
finish
