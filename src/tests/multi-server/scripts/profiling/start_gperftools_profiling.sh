#!/bin/bash
#
#  Run freeradius under the gperftools CPU profiler inside the profiling
#  container.
#
#  Sampling starts switched off.  The server.start trigger begins sampling
#  once the worker threads are running, and the server.stop trigger ends it
#  before the worker threads are torn down, so startup and shutdown stay out
#  of the profile.  The script passes both triggers as -S overrides, so the
#  shared radiusd.conf is the same in service mode and in profiling mode.
#
#  The load generator ends the run.  The test configuration sets
#  on_complete = exit on the load listener.  Once the load generator has
#  sent the configured number of requests and received the answers, the
#  load generator signals the server to exit, and gperftools writes the
#  profile when the server stops.
#
#  PROFILING_RESULT_DIR names the directory that receives every output
#  file.  The compose environment sets the variable and bind mounts the
#  host results directory at that path.
#

: "${PROFILING_RESULT_DIR:?set PROFILING_RESULT_DIR to the directory that receives the profiling output}"

#  pprof converts the raw profile to a report and is part of the profiling
#  image.  Fail before starting the server if it is missing.
command -v pprof >/dev/null 2>&1 || { echo "ERROR: pprof is required for the gperftools capture but is not installed" >&2; exit 1; }

PROFILE="$PROFILING_RESULT_DIR/profile.out"

exec > "$PROFILING_RESULT_DIR/capture.log" 2>&1

#  On shutdown freeradius sends SIGTERM to the whole process group.  Without
#  the trap, SIGTERM would kill this script before the script records the
#  exit status below.  The trap also stops `docker stop` from ending this
#  script with SIGTERM, so `docker stop` waits for the SIGKILL fallback.
trap '' SIGTERM

#  The test template exports every proto_load setting as TEST_LOADGEN_*
echo "proto_load configuration environment variables:"
env | grep '^TEST_LOADGEN_' | sort
echo ""

#
#  freeradius stdout and stderr go to freeradius_gperftools.log.
#
#  CPUPROFILE_FREQUENCY  samples per CPU-second.  A short load costs well
#                        under a second of CPU, so the 100 Hz default would
#                        leave only tens of samples for the whole profile.
#
#  %gperftools.start writes the profile to the file named here.  The
#  server.stop trigger stops the profiler, which flushes the file, before
#  the process exits.
#
echo "INFO: starting freeradius under gperftools at $(date)"
STATUS=0
CPUPROFILE_FREQUENCY=1000 \
freeradius -f -l stdout \
  -S resources.talloc_skip_cleanup=yes \
  -S "trigger.server.start=%gperftools.start('$PROFILE')" \
  -S 'trigger.server.stop=%gperftools.stop()' \
  > "$PROFILING_RESULT_DIR/freeradius.log" 2>&1 || STATUS=$?

#
#  Record how freeradius exited.  A run that a signal killed produces a
#  truncated or absent profile, so the status has to survive to the publish
#  step, which reads this file and refuses to upload an unclean run.  The
#  status is recorded for clean runs too, so an absent file means that the
#  script did not get this far, rather than that the run was fine.
#
echo "${STATUS}" > "$PROFILING_RESULT_DIR/exit-status"

if [ "${STATUS}" -ne 0 ]; then
  if [ "${STATUS}" -gt 128 ]; then
    echo "ERROR: freeradius was killed by signal $((STATUS - 128)); the profile may be truncated" >&2
  else
    echo "ERROR: freeradius exited ${STATUS}; the profile may be truncated" >&2
  fi
  echo "ERROR: see freeradius_gperftools.log for the reason; these results will not be published" >&2
fi

echo "INFO: profiling complete at $(date)"

#
#  Convert in the container, where the build the addresses belong to still
#  exists.  pprof takes the freeradius binary and finds the shared objects
#  through PPROF_BINARY_PATH (libfreeradius-*.so and rlm_*.so install into
#  /usr/lib).  profile.pb.gz bakes the symbols in, so pprof reads it on any
#  host without the build, the way kcachegrind reads callgrind's profile.out.
#
echo "INFO: running pprof to generate the report and the portable profile"
export PPROF_BINARY_PATH=/usr/lib
RADIUSD_BIN=$(readlink -f "$(command -v freeradius)")
pprof -proto "$RADIUSD_BIN" "$PROFILE" > "$PROFILING_RESULT_DIR/profile.pb.gz"
pprof -text -nodefraction=0 "$RADIUSD_BIN" "$PROFILE" > "$PROFILING_RESULT_DIR/report.txt"

#  Discard any output after this point
exec > /dev/null 2>&1
