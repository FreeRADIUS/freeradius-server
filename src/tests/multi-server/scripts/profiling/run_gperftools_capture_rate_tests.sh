#!/bin/bash
#
#  Measure the gperftools capture rate of each suite in SUITES.
#
#  For each suite, measure_gperftools_capture_rate.sh runs a test under
#  gperftools several times with the Docker VM idle and several times
#  beside a CPU hog, then prints the share of freeradius's CPU time that
#  each profile captured.  That script describes the method and the result
#  files.
#
#  Each test is the same one that this command runs:
#
#    make test.multi-server.<suite>.<test> MODE=profiling PROFILING_TOOL=gperftools
#
#  Run from the top of the source tree, after building the profiling image
#  for the checked out commit:
#
#    make docker.radenv-profiling.ubuntu24
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

#
#  Edit SUITES to change the suites that the script measures.
#
SUITES="accept mysql"

case "${1:-}" in
-h|--help) sed -n '/^#  Usage/,/^$/p' "$0"; "$MEASURE" --help; exit 0 ;;
esac

for suite in $SUITES; do
	"$MEASURE" "$@" -s "$suite" || exit
done
