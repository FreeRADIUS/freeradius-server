#!/bin/bash
#
#  Run freeradius under callgrind inside the profiling container.
#
#  Instrumentation starts switched off (--instr-atstart=no), so
#  configuration parsing and module instantiation stay out of the profile.
#  The server.start trigger switches instrumentation on once the worker
#  threads are running, and the server.stop trigger switches
#  instrumentation off before the worker threads are torn down, so
#  shutdown stays out of the profile as well.  The script passes both
#  triggers as -S overrides, so the shared radiusd.conf is the same in
#  service mode and in profiling mode.
#
#  The load generator ends the run.  The test configuration sets
#  on_complete = exit on the load listener.  Once the load generator has
#  sent the configured number of requests and received the answers, the
#  load generator signals the server to exit, and callgrind writes the
#  profile dump when the process exits.
#
#  PROFILING_RESULT_DIR names the directory that receives every output
#  file.  The compose environment sets the variable and bind mounts the
#  host results directory at that path.
#

: "${PROFILING_RESULT_DIR:?set PROFILING_RESULT_DIR to the directory that receives the profiling output}"

exec > "$PROFILING_RESULT_DIR/valgrind_profiling.log" 2>&1

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
#  valgrind logs to --log-file.  freeradius stdout and stderr go to
#  freeradius.log.
#
#  --trace-children=yes    also profile child processes, each writes a
#                          separate callgrind.out.%p
#  --separate-threads=no   one profile per process, not per thread
#  --separate-callers=6    separate each function's costs by up to 6
#                          callers in the call chain
#  --dump-instr=yes        per-instruction counts (assembly-level inspection)
#  --collect-jumps=yes     record jumps for intra-function control flow
#  --cache-sim=yes         cache counters (Dr/Dw data reads and writes, L1
#                          and last-level misses) for the cycle estimate (CEst)
#  --branch-sim=yes        branch mispredict counters (Bc conditional, Bi
#                          indirect) for CEst
#  --keep-debuginfo=yes    keep symbols for code unloaded with dlclose(),
#                          so late dumps resolve names
#  --instr-atstart=no      start with instrumentation off.  The
#                          server.start and server.stop triggers switch
#                          instrumentation on and off
#
echo "INFO: starting freeradius under callgrind at $(date)"
VALGRIND_STATUS=0
valgrind \
  --tool=callgrind \
  --log-file="$PROFILING_RESULT_DIR/valgrind.log" \
  --callgrind-out-file="$PROFILING_RESULT_DIR/callgrind.out.%p" \
  --trace-children=yes \
  --separate-threads=no \
  --separate-callers=6 \
  --dump-instr=yes \
  --collect-jumps=yes \
  --cache-sim=yes \
  --branch-sim=yes \
  --keep-debuginfo=yes \
  --instr-atstart=no \
  freeradius -f -l stdout \
    -S resources.talloc_skip_cleanup=yes \
    -S 'trigger.server.start=%callgrind.start()' \
    -S 'trigger.server.stop=%callgrind.stop()' \
  > "$PROFILING_RESULT_DIR/freeradius.log" 2>&1 || VALGRIND_STATUS=$?

#
#  Record how valgrind exited.  A run in which a signal killed valgrind
#  produces truncated callgrind output, and the numbers in truncated output
#  are not comparable with a clean run.  The publish step reads this file
#  and refuses to upload an unclean run, so the status has to survive until
#  the publish step.  The script records the status for clean runs too, so
#  an absent file means that the wrapper did not get this far, rather than
#  that the run was fine.
#
echo "${VALGRIND_STATUS}" > "$PROFILING_RESULT_DIR/valgrind-exit-status"

if [ "${VALGRIND_STATUS}" -ne 0 ]; then
  #  An exit status over 128 means that a signal killed valgrind.  139 is
  #  SIGSEGV, which is how valgrind exits when the brk segment reaches the
  #  8 MB ceiling.  valgrind.log names the real reason on the line above
  #  the backtrace.
  if [ "${VALGRIND_STATUS}" -gt 128 ]; then
    echo "ERROR: valgrind was killed by signal $((VALGRIND_STATUS - 128)); profiling data is truncated" >&2
  else
    echo "ERROR: valgrind exited ${VALGRIND_STATUS}; profiling data may be truncated" >&2
  fi
  echo "ERROR: see valgrind.log for the reason; these results will not be published" >&2
fi

echo "INFO: profiling complete at $(date)"

echo "INFO: running callgrind_annotate to generate report"
callgrind_annotate \
  $(find "$PROFILING_RESULT_DIR" -maxdepth 1 -name "callgrind.out.*" -size +0c | sort) \
  > "$PROFILING_RESULT_DIR/callgrind_report.txt"

#  Discard any output after this point
exec > /dev/null 2>&1
