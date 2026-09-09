#!/bin/bash
#
#  Run one multi-server test: start radenv once per run name, and dump the
#  logs of a failing run. The test.multi-server.<suite>.<test> target in
#  all.mk resolves the make-side settings into the environment below and
#  calls this script, so a developer can repeat a single test by hand
#  without make.
#
#  Usage: run_test.sh <suite> <test> <output-dir>
#
#  Environment, all set by all.mk:
#    MODE                        service | profiling
#    RUNS                        space-separated run names: 'service', or the
#                                profilers named by TOOL in profiling mode
#    FREERADIUS_SERVICE_IMAGE    image for MODE=service
#    FREERADIUS_PROFILING_IMAGE  image for MODE=profiling
#    PROFILING_RESULT_ROOT       prof-results directory
#    PROFILING_RESULT_MODE       ci | dev result layout, see all.mk
#    GIT_BRANCH, GIT_COMMIT      path components of the ci layout
#    TOP_SRCDIR                  repository root, passed through to compose
#    RADENV                      the radenv binary
#    RADENV_FLAGS                extra radenv arguments (TEST_MULTI_SERVER_FLAGS)
#
set -u

if [ $# -ne 3 ]; then
  echo "Usage: ${0##*/} <suite> <test> <output-dir>" >&2
  exit 2
fi
SUITE=$1
TEST=$2
OUTDIR=$3
TARGET="test.multi-server.${SUITE}.${TEST}"

echo "MULTI-SERVER-TEST ${TARGET} (MODE=${MODE} RUNS=${RUNS})"

#  This script fixes the image, the PROFILING flag, and the result path once
#  per test. Every profiler in RUNS writes into the same PROFILING_RESULT_PATH.
#  The result directory holds the files of every profiler for one test, and
#  each capture script uses distinct file names, so the files do not collide.
if [ "$MODE" = "profiling" ]; then
  FREERADIUS_IMAGE=$FREERADIUS_PROFILING_IMAGE
  PROFILING=yes
  if [ "$PROFILING_RESULT_MODE" = "dev" ]; then
    PROFILING_RESULT_PATH="${PROFILING_RESULT_ROOT}/${SUITE}/${TEST}"
  else
    RUN_BASE="${PROFILING_RESULT_ROOT}/${GIT_BRANCH}/${GIT_COMMIT}"
    EXISTING=$(find "$RUN_BASE" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
    PROFILING_RESULT_PATH="${RUN_BASE}/$(( EXISTING + 1 ))/${SUITE}/${TEST}"
  fi
  mkdir -p "$PROFILING_RESULT_PATH"
  echo "PROFILING_RESULT_PATH: ${PROFILING_RESULT_PATH}"
else
  FREERADIUS_IMAGE=$FREERADIUS_SERVICE_IMAGE
  PROFILING=no
  #  The compose files bind mount the results directory in every mode, so
  #  service mode needs a placeholder path.
  PROFILING_RESULT_PATH=/tmp/prof-results-unused
fi

#  Print every log and listener file of a failed run, so a CI failure is
#  readable from the job log alone.
dump_logs() {
  local f
  for f in "$1"/* "$2"/*; do
    [ -f "$f" ] || continue
    echo ""
    echo "=== $f ==="
    case "$f" in
      */listener/*)
        echo "-- line-type counts --"
        awk '{print $1}' "$f" | sort | uniq -c
        echo "-- last 200 lines --"
        ;;
    esac
    tail -200 "$f"
  done
}

#  The loop starts radenv once per run name, one run at a time. Each run
#  writes logs and listener files to a per-run subdirectory. The first
#  failing run stops the loop.
for RUN in $RUNS; do
  if [ "$PROFILING" = "yes" ]; then PROFILING_TOOL=$RUN; else PROFILING_TOOL=""; fi
  LOG_DIR="${OUTDIR}/logs/${RUN}"
  LISTENER_DIR="${OUTDIR}/listener/${RUN}"
  mkdir -p "$LOG_DIR" "$LISTENER_DIR"
  echo "MULTI-SERVER-TEST ${TARGET} run=${RUN}"

  # shellcheck disable=SC2086  # RADENV_FLAGS is a list of arguments
  if ! DATA_PATH="$OUTDIR" \
       TOP_SRCDIR="$TOP_SRCDIR" \
       FREERADIUS_IMAGE="$FREERADIUS_IMAGE" \
       PROFILING="$PROFILING" \
       PROFILING_TOOL="$PROFILING_TOOL" \
       PROFILING_RESULT_PATH="$PROFILING_RESULT_PATH" \
       "$RADENV" ${RADENV_FLAGS:-} \
         --project-name "${SUITE}-${TEST}-${MODE}" \
         --compose "${OUTDIR}/environment.yml" \
         --test "${OUTDIR}/template.yml" \
         --use-files \
         --listener-dir "$LISTENER_DIR" \
         --log-dir "$LOG_DIR" \
         --output "${LOG_DIR}/result.log" \
         > "${LOG_DIR}/stdout.log" 2> "${LOG_DIR}/stderr.log"; then
    echo "FAILED: ${TARGET} (MODE=${MODE} run=${RUN})"
    dump_logs "$LOG_DIR" "$LISTENER_DIR"
    exit 1
  fi
done
