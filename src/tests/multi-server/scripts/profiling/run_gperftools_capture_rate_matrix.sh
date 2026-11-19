#!/bin/bash
#
#  Run every batch of the gperftools capture rate study, one after the
#  other.
#
#  A batch is one profiler configuration and one test.  For each suite of
#  a gperftools batch, the script runs measure_gperftools_capture_rate.sh
#  with the image, the test, and the results label of the batch.  The
#  batches() function below lists the batches.
#
#  Before each batch, the script writes the profiler settings of the batch
#  into start_gperftools_profiling.sh.  On exit, the script restores that
#  file.
#
#  Each run of the script has a name, and the results of a batch go to
#  prof-results/<name>-<batch>/<image>/.  Because the default name holds
#  the start time, a new run does not overwrite the results of an earlier
#  run.  The script also writes:
#
#    prof-results/<name>.log          the output of every batch
#    prof-results/<name>-results.csv  one row for each complete test run
#
#  Run from the top of the source tree:
#
#    src/tests/multi-server/scripts/profiling/run_gperftools_capture_rate_matrix.sh
#
#  Where caffeinate exists, the script re-runs itself under caffeinate -i.
#  The machine then does not sleep until the last batch ends.
#
#  Usage: run_gperftools_capture_rate_matrix.sh [options]
#
#    -n            print each batch and the commands of the batch, and
#                  change nothing
#    -b <number>   start at this batch
#    -e <number>   end after this batch
#    -r <name>     name of the run (default: matrix-<date>-<time>).  To
#                  continue an interrupted run, give the name of that run
#                  and the number of the first batch to repeat.
#    -h, --help    print this help
#

set -u

usage() { sed -n '/^#  Usage/,/^$/p' "$0"; }

DIR=src/tests/multi-server/scripts/profiling
TESTS=src/tests/multi-server/tests
MEASURE=$DIR/measure_gperftools_capture_rate.sh
CAPTURE=$DIR/start_gperftools_profiling.sh

#
#  Tags of freeradius4-radenv-profiling/ubuntu24.  The UNPATCHED image has
#  no ProfilerRegisterThread() call.  The PATCHED image has the call.
#
#  To build an image, check out the master branch for UNPATCHED or this
#  branch for PATCHED, and run:
#
#    make docker.radenv-profiling.ubuntu24
#
#  The tag of the image is the short commit of the tree.  To use other
#  tags, set UNPATCHED and PATCHED in the environment.
#
UNPATCHED=${UNPATCHED:-3e793f62f4}
PATCHED=${PATCHED:-c601ba9ef7}

#
#  The four profiler configurations:
#
#    name|image|Hz|per-thread timers
#
configs() {
	cat <<EOF
unpatched-1000hz|$UNPATCHED|1000|0
unpatched-100hz|$UNPATCHED|100|0
patched-1000hz|$PATCHED|1000|1
patched-100hz|$PATCHED|100|1
EOF
}

#
#  Print one batch for each of the four configurations.
#
#    four <test> <suites> <arms> <minutes> <batch suffix>
#
four() {
	configs | while IFS='|' read -r name image hz pt; do
		echo "gperftools|$name-$5|$image|$hz|$pt|$1|$2|$3|$4"
	done
}

#
#  One line for each batch:
#
#    kind|batch|image|Hz|per-thread timers|test|suites|arms|minutes
#
#  'kind' is gperftools or callgrind.  'minutes' is the expected length of
#  the batch.  A callgrind batch runs each test once under valgrind, and
#  ignores the Hz, per-thread timers, and arms fields.
#
#  Batches 1 to 16 test one configuration each.  From batch 17, each group
#  of four batches tests the four configurations with the same test.
#
batches() {
	cat <<EOF
gperftools|unpatched-short_ci-100pps|$UNPATCHED|1000|0|short_ci|accept mysql|idle stress|46
gperftools|patched-short-500pps|$PATCHED|100|1|short_500pps|accept mysql|idle stress|46
gperftools|patched-short-200pps|$PATCHED|100|1|short_200pps|accept mysql|idle stress|46
gperftools|patched-short-300pps|$PATCHED|100|1|short_300pps|accept mysql|idle stress|46
gperftools|patched-short-400pps|$PATCHED|100|1|short_400pps|accept mysql|idle stress|46
gperftools|unpatched-5min-100pps|$UNPATCHED|1000|0|5min|accept mysql|idle stress|116
gperftools|patched-1000hz-short_ci-100pps|$PATCHED|1000|1|short_ci|accept mysql|idle stress|46
gperftools|unpatched-100hz-short_ci-100pps|$UNPATCHED|100|0|short_ci|accept mysql|idle stress|46
gperftools|patched-5min-500pps-accept-idle|$PATCHED|100|1|5min_500pps|accept|idle|30
gperftools|patched-5min-470pps-accept-idle|$PATCHED|100|1|5min_470pps|accept|idle|30
gperftools|unpatched-5min-500pps|$UNPATCHED|1000|0|5min_500pps|accept mysql|idle stress|116
callgrind|callgrind-short_ci-100pps|$UNPATCHED|-|-|short_ci|accept mysql|-|10
gperftools|patched-short_ci-100pps|$PATCHED|100|1|short_ci|accept mysql|idle stress|46
gperftools|patched-5min-100pps|$PATCHED|100|1|5min|accept mysql|idle stress|116
gperftools|patched-short-499pps|$PATCHED|100|1|short_499pps|accept mysql|idle stress|46
gperftools|patched-5min-499pps|$PATCHED|100|1|5min_499pps|accept mysql|idle stress|116
EOF
	four short_499pps "accept mysql" idle 22 short-499pps-idle
	four short_470pps "accept mysql" idle 22 short-470pps-idle
	four 5min_499pps "accept mysql" idle 58 5min-499pps-idle
	four 5min_470pps "accept mysql" idle 58 5min-470pps-idle
	four short_ci "accept mysql" idle 22 short_ci-100pps-idle
	echo "callgrind|callgrind-short_ci-100pps-rerun|$UNPATCHED|-|-|short_ci|accept mysql|-|10"
	four short_499pps mysql stress 12 short-499pps-mysql-stress
	four short_470pps mysql stress 12 short-470pps-mysql-stress
	four short_499pps accept stress 12 short-499pps-accept-stress
	four short_470pps accept stress 12 short-470pps-accept-stress
}

DRY=0
FIRST=1
LAST=999
RUN=matrix-$(date +%Y%m%d-%H%M)

[ "${1:-}" = --help ] && { usage; exit 0; }
while getopts "nb:e:r:h" opt; do
	case $opt in
	n) DRY=1 ;;
	b) FIRST=$OPTARG ;;
	e) LAST=$OPTARG ;;
	r) RUN=$OPTARG ;;
	h) usage; exit 0 ;;
	*) usage; exit 1 ;;
	esac
done

[ -f src/tests/multi-server/all.mk ] || { echo "ERROR: run from the top of the source tree" >&2; exit 1; }

#
#  The test short_200pps is the file short.200pps.test.yml.
#
while IFS='|' read -r kind batch image hz pt test suites arms minutes; do
	for suite in $suites; do
		file=$TESTS/$suite/$(echo "$test" | tr _ .).test.yml
		[ -f "$file" ] || { echo "ERROR: batch $batch needs $file" >&2; exit 1; }
	done
done <<EOF
$(batches)
EOF

if [ "$DRY" = 1 ]; then
	n=0; total=0
	while IFS='|' read -r kind batch image hz pt test suites arms minutes; do
		n=$((n + 1))
		[ "$n" -lt "$FIRST" ] && continue
		[ "$n" -gt "$LAST" ] && continue
		total=$((total + minutes))
		echo "batch $n: $batch (about $minutes min, ends $total min after the start)"
		for suite in $suites; do
			if [ "$kind" = callgrind ]; then
				echo "    make -f src/tests/multi-server/all.mk test.multi-server.$suite.$test MODE=profiling PROFILING_TOOL=valgrind GIT_COMMIT=$image GIT_BRANCH=$RUN-$batch PROFILING_RUN_INDEX=callgrind-1"
			else
				echo "    profiler: $hz Hz, per-thread timers $pt"
				echo "    $MEASURE -s $suite -t $test -l $RUN-$batch -c $image -a \"$arms\""
			fi
		done
	done <<EOF
$(batches)
EOF
	echo "total: about $total min.  Nothing was run or changed."
	exit 0
fi

if pgrep -f measure_gperftools_capture_rate >/dev/null; then
	echo "ERROR: a capture rate run is in progress" >&2
	exit 1
fi

for image in $UNPATCHED $PATCHED; do
	docker image inspect "freeradius4-radenv-profiling/ubuntu24:$image" >/dev/null 2>&1 || {
		echo "ERROR: image freeradius4-radenv-profiling/ubuntu24:$image not found" >&2
		exit 1
	}
done

#
#  Under caffeinate -i, the machine does not sleep during the run.
#
if [ -z "${CAPTURE_RATE_MATRIX_AWAKE:-}" ] && command -v caffeinate >/dev/null; then
	CAPTURE_RATE_MATRIX_AWAKE=1 exec caffeinate -i "$0" -r "$RUN" -b "$FIRST" -e "$LAST"
fi

mkdir -p prof-results
LOG=prof-results/$RUN.log
CSV=prof-results/$RUN-results.csv
exec > >(tee -i -a "$LOG") 2>&1

BACKUP=$(mktemp)
cp "$CAPTURE" "$BACKUP"
trap 'cat "$BACKUP" > "$CAPTURE"; rm -f "$BACKUP"' EXIT
trap 'exit 130' INT TERM

#
#  Write the sampling frequency ($1) and the per-thread timers setting
#  ($2, 0 or 1) into start_gperftools_profiling.sh.
#
set_profiler() {
	awk -v hz="$1" -v pt="$2" '
		/^CPUPROFILE_PER_THREAD_TIMERS=/ { next }
		/^CPUPROFILE_FREQUENCY=/ {
			print "CPUPROFILE_FREQUENCY=" hz " \\"
			if (pt == 1) print "CPUPROFILE_PER_THREAD_TIMERS=1 \\"
			next
		}
		{ print }
	' "$BACKUP" > "$CAPTURE"
}

#
#  Write one row for each complete test run of every batch to $CSV.
#
write_results() {
	echo "batch,image,frequency_hz,per_thread_timers,test,suite,arm,run,window_s,samples,capture_pct,exit" > "$CSV"
	while IFS='|' read -r kind batch image hz pt test suites arms minutes; do
		[ "$kind" = gperftools ] || continue
		for suite in $suites; do
			[ -f "prof-results/$RUN-$batch/$image/$suite-capture-rate.csv" ] || continue
			awk -F, -v b="$batch" -v i="$image" -v pt="$pt" -v t="$test" -v s="$suite" 'NR > 1 {
				split($1, r, "-")
				print b "," i "," $2 "," pt "," t "," s "," r[2] "," r[3] "," $3 "," $4 "," $5 "," $6
			}' "prof-results/$RUN-$batch/$image/$suite-capture-rate.csv" >> "$CSV"
		done
	done <<EOF
$(batches)
EOF
}

echo "run $RUN, batches $FIRST to $LAST, $(date '+%F %T')"

#
#  The batch list is on file descriptor 3, because the tests read the
#  standard input.
#
n=0
while IFS='|' read -r kind batch image hz pt test suites arms minutes <&3; do
	n=$((n + 1))
	[ "$n" -lt "$FIRST" ] && continue
	[ "$n" -gt "$LAST" ] && continue
	echo
	echo "##### batch $n: $batch, $(date '+%F %T'), about $minutes min"

	for suite in $suites; do
		if [ "$kind" = callgrind ]; then
			make -f src/tests/multi-server/all.mk "test.multi-server.$suite.$test" \
				MODE=profiling PROFILING_TOOL=valgrind GIT_COMMIT="$image" \
				GIT_BRANCH="$RUN-$batch" PROFILING_RUN_INDEX=callgrind-1
		else
			set_profiler "$hz" "$pt"
			"$MEASURE" -s "$suite" -t "$test" -l "$RUN-$batch" -c "$image" -a "$arms"
		fi
		status=$?
		[ "$status" = 130 ] && exit 130
		[ "$status" = 0 ] || echo "WARNING: batch $n ($batch), suite $suite, ended with status $status"
	done
	write_results
done 3<<EOF
$(batches)
EOF

echo
echo "run $RUN complete, $(date '+%F %T')"
echo "results table written to $CSV"
