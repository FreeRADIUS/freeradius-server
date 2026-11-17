#!/bin/bash
#
#  Measure the gperftools capture rate of the accept suite, then of the
#  mysql suite.
#
#  For each suite, measure_gperftools_capture_rate.sh runs the short_ci
#  test under gperftools several times with the Docker VM idle and several
#  times beside a CPU hog, then prints the share of freeradius's CPU time
#  that each profile captured.  That script describes the method and the
#  result files.
#
#  Each test is the same one that this command runs:
#
#    make test.multi-server.<suite>.short_ci MODE=profiling PROFILING_TOOL=gperftools
#
#  Run from the top of the source tree, after building the profiling image
#  for the checked out commit:
#
#    make docker.radenv-profiling.ubuntu24
#
#  The two suites take about 45 minutes.
#
#  Usage: run_gperftools_capture_rate_tests.sh [options]
#
#    -h, --help    print this help, then the help of
#                  measure_gperftools_capture_rate.sh
#
#    The script passes every other option to
#    measure_gperftools_capture_rate.sh once per suite, and overrides -s.
#

MEASURE=$(dirname "$0")/measure_gperftools_capture_rate.sh

case "${1:-}" in
-h|--help) sed -n '/^#  Usage/,/^$/p' "$0"; "$MEASURE" --help; exit 0 ;;
esac

for suite in accept mysql; do
	"$MEASURE" "$@" -s "$suite" || exit
done
