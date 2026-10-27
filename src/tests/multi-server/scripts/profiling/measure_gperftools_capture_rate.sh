#!/bin/bash
#
#  Measure how much of freeradius's CPU time the gperftools profile
#  captures, by running a suite's short_ci test under gperftools several
#  times.
#
#  The capture rate of a run is the CPU time the profile recorded
#  (samples / frequency) divided by the CPU time freeradius used while the
#  profiler ran.  The server.start and server.stop triggers log
#  /proc/self/stat as the profiler starts and stops, and the difference
#  of utime + stime between the two is the CPU time of the profiled window.
#
#  Each run can execute in one of two arms:
#
#    idle    nothing else runs in the Docker VM.
#    stress  a container runs two busy loops per Docker CPU, so freeradius
#            competes for CPU the way it does on a shared CI runner.
#
#  The arms alternate within each run index, so drift over the batch
#  affects both arms alike.
#
#  The script changes no files.  The profiler settings come from the source
#  tree, so set them there before running:
#
#    environments/<suite>.yml.j2         TRIGGER_SERVER_START_APPEND and
#                                        TRIGGER_SERVER_STOP_APPEND log
#                                        /proc/self/stat (tests/<suite>/
#                                        environment.yml.j2 links to it)
#    scripts/profiling/
#      start_gperftools_profiling.sh     CPUPROFILE_FREQUENCY and
#                                        CPUPROFILE_PER_THREAD_TIMERS
#
#  Run from the top of the source tree.  Each run takes about two minutes,
#  because the test harness waits out its 120 s state timeout.
#
#  Usage: measure_gperftools_capture_rate.sh [options]
#
#    -s <suite>    suite whose short_ci test runs (default: accept)
#    -c <sha>      image to test, freeradius4-radenv-profiling/ubuntu24:<sha>
#                  (default: short SHA of HEAD)
#    -n <runs>     runs per arm (default: 3)
#    -a "<arm>..." arms to run, idle and/or stress (default: "idle stress")
#    -l <label>    results go to prof-results/<label>/<sha>/ (default: capture-rate)
#    -h            print this help
#

set -u

usage() { sed -n '/^#  Usage/,/^$/p' "$0"; }

COMMIT=$(git rev-parse --short HEAD 2>/dev/null)
SUITE=accept
RUNS=3
ARMS="idle stress"
LABEL=capture-rate

[ "${1:-}" = --help ] && { usage; exit 0; }
while getopts "s:c:n:a:l:h" opt; do
	case $opt in
	s) SUITE=$OPTARG ;;
	c) COMMIT=$OPTARG ;;
	n) RUNS=$OPTARG ;;
	a) ARMS=$OPTARG ;;
	l) LABEL=$OPTARG ;;
	h) usage; exit 0 ;;
	*) usage; exit 1 ;;
	esac
done

[ -f src/tests/multi-server/all.mk ] || { echo "ERROR: run from the top of the source tree" >&2; exit 1; }

IMAGE=freeradius4-radenv-profiling/ubuntu24:$COMMIT
HOG=capture-rate-hog
COMPOSE=src/tests/multi-server/tests/$SUITE/environment.yml.j2
CAPTURE=src/tests/multi-server/scripts/profiling/start_gperftools_profiling.sh
RESULTS=prof-results/$LABEL/$COMMIT
MAKE_ARGS="MODE=profiling PROFILING_TOOL=gperftools GIT_COMMIT=$COMMIT GIT_BRANCH=$LABEL"

grep -q "TRIGGER_SERVER_STOP_APPEND:.*/proc/self/stat" "$COMPOSE" || {
	echo "ERROR: $COMPOSE does not log /proc/self/stat from the server triggers" >&2
	exit 1
}

HZ=$(sed -n 's/^CPUPROFILE_FREQUENCY=\([0-9]*\) .*/\1/p' "$CAPTURE")
[ -n "$HZ" ] || { echo "ERROR: no CPUPROFILE_FREQUENCY line in $CAPTURE" >&2; exit 1; }
PER_THREAD=0
grep -q '^CPUPROFILE_PER_THREAD_TIMERS=1 ' "$CAPTURE" && PER_THREAD=1

#
#  make looks the image up by tag and does not build it here.  The docker
#  stamp under build/docker/ only depends on the Dockerfile, so after a
#  commit change, remove the stamp before building the image.
#
docker image inspect "$IMAGE" >/dev/null 2>&1 || {
	echo "ERROR: $IMAGE not found.  Build it with:" >&2
	echo "  rm -f build/docker/stamp-image.ubuntu24.radenv-profiling" >&2
	echo "  make -f src/tests/multi-server/all.mk freeradius-prof.image" >&2
	exit 1
}

#
#  Per-thread timers only cover threads that call ProfilerRegisterThread().
#  On a build without that call, the worker, network and coordinator
#  threads get no timer and go unsampled.
#
if [ "$PER_THREAD" = 1 ] && ! docker run --rm --entrypoint sh "$IMAGE" \
	-c 'nm -D /usr/lib/libfreeradius-io.so | grep -q ProfilerRegisterThread'; then
	echo "ERROR: $IMAGE does not call ProfilerRegisterThread(), remove CPUPROFILE_PER_THREAD_TIMERS from $CAPTURE" >&2
	exit 1
fi

CLK_TCK=$(docker run --rm --entrypoint getconf "$IMAGE" CLK_TCK)
HOGS=$(( $(docker info --format '{{.NCPU}}') * 2 ))

trap 'docker rm -f "$HOG" >/dev/null 2>&1' EXIT

#
#  Two busy loops per Docker CPU.  The hog runs in the profiling image,
#  which is known to exist.
#
start_hog() {
	docker run -d --rm --name "$HOG" --entrypoint bash "$IMAGE" \
		-c "for i in \$(seq $HOGS); do (while :; do :; done) & done; wait" >/dev/null
	[ "$(docker inspect -f '{{.State.Running}}' "$HOG" 2>/dev/null)" = true ] || { echo "ERROR: CPU hog did not start" >&2; exit 1; }
}

echo "suite $SUITE, image $IMAGE, frequency $HZ Hz, per-thread timers $PER_THREAD, $RUNS run(s) per arm ($ARMS)"
echo "results in $RESULTS"

for i in $(seq 1 "$RUNS"); do
	for arm in $ARMS; do
		run=f$HZ-$arm-$i
		[ "$arm" = stress ] && start_hog
		echo "=== $run $(date +%T)"
		make -f src/tests/multi-server/all.mk test.multi-server.$SUITE.short_ci $MAKE_ARGS \
			PROFILING_RUN_INDEX="$run" 2>&1 | grep -E 'FAILED|WARNING|interrupts'
		[ "$arm" = stress ] && docker rm -f "$HOG" >/dev/null
	done
done

#
#  One row per run.  The comm field of /proc/self/stat ends in ") ", so
#  utime and stime are fields 12 and 13 after it.
#
CSV=$RESULTS/$SUITE-capture-rate.csv
echo "run,frequency,window_s,samples,capture_pct,exit" > "$CSV"
printf '\n%-22s %9s %8s %9s %8s\n' run window_s samples capture exit
for d in "$RESULTS"/f*-*-*; do
	g=$d/$SUITE/short_ci/gperftools
	run=${d##*/}
	hz=${run#f}; hz=${hz%%-*}
	ticks() { grep "(trigger-server.$1)" "$g/freeradius.log" 2>/dev/null | sed 's/.*) //' | awk '{ print $12 + $13 }'; }
	awk -v run="$run" -v hz="$hz" -v tck="$CLK_TCK" \
	    -v s="$(ticks start)" -v e="$(ticks stop)" \
	    -v n="$(grep -o 'bytes = [0-9]*' "$g/stats.txt" 2>/dev/null | awk '{ print $3 }')" \
	    -v x="$(cat "$g/exit-status" 2>/dev/null)" -v csv="$CSV" 'BEGIN {
		if (s == "" || e == "" || n == "") { printf "%-22s incomplete\n", run; exit }
		w = (e - s) / tck
		c = 100 * (n / hz) / w
		printf "%-22s %9.2f %8d %8.1f%% %8s\n", run, w, n, c, x
		printf "%s,%s,%.2f,%d,%.1f,%s\n", run, hz, w, n, c, x >> csv
	}'
done
echo "table written to $CSV"
