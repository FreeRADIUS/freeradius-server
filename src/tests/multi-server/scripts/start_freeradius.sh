#!/bin/bash
#
#  Container entry point for the multi-server suites that profile FreeRADIUS
#  which is called by the testcase templates.
#
#  Common script that exports the env variables required by proto_load
#  before running the valgrind or gperftools start scripts.
#
#    PROFILING=no   (service mode)    exec freeradius normally
#    PROFILING=yes  (profiling mode)  exec start_${PROFILING_TOOL}_profiling.sh
#
set -u

#  TEST_LOADGEN_MAX_REQUESTS is the total request count. Each pps
#  step from start_pps up to and including max_pps sends TEST_LOADGEN_DURATION
#  seconds of packets.
TEST_LOADGEN_MAX_REQUESTS=0
for ((pps=TEST_LOADGEN_START_PPS; pps<=TEST_LOADGEN_MAX_PPS; pps+=TEST_LOADGEN_STEP)); do
  TEST_LOADGEN_MAX_REQUESTS=$((TEST_LOADGEN_MAX_REQUESTS + TEST_LOADGEN_DURATION * pps))
done
export TEST_LOADGEN_MAX_REQUESTS

echo "Starting freeradius with the following load-generator configuration:"
env | grep '^TEST_LOADGEN_' | sort | sed 's/^/  /'

if [ "${PROFILING:-no}" != "yes" ]; then
  #  Not profiling, start freeradius normally
  exec freeradius -f -l stdout -S resources.talloc_skip_cleanup=yes
else
  # We are profiling, call the appropriate start script
  PROFILING_SCRIPT="/usr/local/bin/start_${PROFILING_TOOL:-}_profiling.sh"
  if [ -z "${PROFILING_TOOL:-}" ] || [ ! -r "$PROFILING_SCRIPT" ]; then
    echo "ERROR: not starting freeradius, PROFILING=yes but PROFILING_TOOL='${PROFILING_TOOL:-}' isn't currently supported" >&2
    exit 1
  fi

  echo "Profiling with $PROFILING_TOOL ($PROFILING_SCRIPT)"
  exec bash "$PROFILING_SCRIPT"
fi
