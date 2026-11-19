# Profiling report helpers

The capture scripts `start_valgrind_profiling.sh` and
`start_gperftools_profiling.sh` each convert a raw profile into a `report.txt`
in the result directory during the run.  The commands below run the same
conversions by hand, and produce extra views that the capture scripts do not
write.

Run every command from a container that holds the build that produced the
profile, so the profiling tools resolve the function symbols.

Each capture writes into its own result directory, named for the profiler
(`prof-results/.../<suite>/<test>/<tool>/`).  Both profilers name the raw
profile `profile.out` (callgrind adds a `.<pid>` suffix) and both write
`report.txt`, and the separate directories keep the two sets of files apart.

## callgrind results

`start_valgrind_profiling.sh` writes one `profile.out.<pid>` per process.  The
`--separate-threads=no` option keeps every worker thread in a single dump.
`start_valgrind_profiling.sh` then runs `callgrind_annotate` to produce
`report.txt`.  To repeat the text report by hand:

```
callgrind_annotate $(find . -name "profile.out.*" -size +0c | sort) > report.txt
```

### Call graph

`gprof2dot` and `dot` render a `profile.out.<pid>` dump as a Scalable Vector
Graphics (SVG) call graph.

Dependency: `brew install gprof2dot`

```
gprof2dot --format=callgrind <path-to-prof-results>/profile.out.<pid> \
  | dot -Tsvg -o callgraph.svg
```

## gperftools results

`start_gperftools_profiling.sh` converts the raw profile in the container,
where the build that produced the profile still exists.  To repeat the
conversion by hand, run these commands from a container that holds the same
build.  `PPROF_BINARY_PATH` points pprof at the shared objects
(`libfreeradius-*.so` and `rlm_*.so` are installed under `/usr/lib`).
`readlink -f "$(command -v freeradius)"` resolves the freeradius binary that
produced the profile:

```
export PPROF_BINARY_PATH=/usr/lib
RADIUSD_BIN=$(readlink -f "$(command -v freeradius)")
pprof -text  "$RADIUSD_BIN" profile.out > report.txt
pprof -proto "$RADIUSD_BIN" profile.out > profile.pb.gz
```

`profile.pb.gz` holds the resolved symbols, so pprof reads `profile.pb.gz` on
any host without the build:

```
pprof -text profile.pb.gz
pprof -http=:8080 profile.pb.gz
```

## gperftools capture rate tests

`run_gperftools_capture_rate_tests.sh` measures the share of the freeradius
CPU time that the gperftools profile records.  The script runs the `short_ci`
test of the `accept` and `mysql` suites.  Each test runs with the Docker VM
idle, and again beside a container that runs busy loops.

Run every command from the top of the source tree:

```
# Remove every locally built image (optional).
make docker.clean

# Remove the image stamps, or make may skip the image build.
make docker.reset

# Build the profiling image for the checked out commit.
make docker.radenv-profiling.ubuntu24

# Run both suites.  Takes about 45 minutes.
src/tests/multi-server/scripts/profiling/run_gperftools_capture_rate_tests.sh

# Print the results.
cat prof-results/capture-rate/$(git rev-parse --short HEAD)/*-capture-rate.csv
```

The script prints a table for each suite, and writes each complete row to
`<suite>-capture-rate.csv`.

The script copies the container logs to `<run>/<suite>/logs/`.

When the kernel writes a `core` file for a freeradius crash, the script
writes the stack of every thread to `backtrace.txt`.  Both files are in
`<run>/<suite>/<test>/gperftools/`.  The kernel does not write a `core`
file for a crash that the freeradius fault handler catches.

### Overnight runs

`run_gperftools_capture_rate_matrix.sh` runs a list of batches, one after the
other.  A batch is one profiler configuration and one test.  For each suite of
a batch, the script runs the test 5 times for each arm of the batch.  The arms
are idle (the Docker VM is idle) and stress (a container runs busy loops).  A
batch with a name that starts with `callgrind` runs the test of each suite
one time under valgrind, without arms.

The script needs two profiling images.  Build the unpatched image from the
'master' branch, and build the patched image from this branch.  The `make`
target tags each image with the short commit of the checked out tree.

Run every command from the top of the source tree, in the same terminal:

```
# Build the unpatched image.
git checkout master
make docker.reset
make docker.radenv-profiling.ubuntu24
export UNPATCHED=$(git rev-parse --short HEAD)

# Build the patched image.
git checkout -
make docker.reset
make docker.radenv-profiling.ubuntu24
export PATCHED=$(git rev-parse --short HEAD)

# Print the number, the name, and the expected length of every batch.  The
# last line is the total length.  The -n option does not run a batch.
src/tests/multi-server/scripts/profiling/run_gperftools_capture_rate_matrix.sh -n

# Run a range of batches.  The example runs batches 17 to 45.
src/tests/multi-server/scripts/profiling/run_gperftools_capture_rate_matrix.sh -b 17 -e 45

# Alternatively, run every batch.
src/tests/multi-server/scripts/profiling/run_gperftools_capture_rate_matrix.sh
```

The whole list takes more than one night.  To choose a range for one night,
use the lengths that the `-n` option prints.

The script reads the image tags from `UNPATCHED` and `PATCHED` in the
environment.  When a variable is not set, the script uses the default tag on
the `UNPATCHED=` or `PATCHED=` line of the script.

During a run:

1. Keep the terminal open.  On macOS, the script runs under `caffeinate -i`,
   and the machine does not go into idle sleep.
2. Do not switch branch, and do not edit the scripts or the test files.  Each
   batch reads the scripts and the test files from the source tree.
3. Do not run other containers.  The load of another container changes the
   results of the idle arm.
4. Do not edit or commit `start_gperftools_profiling.sh`.  The script writes
   the profiler settings of each batch into the file, and restores the file
   when the script exits.

To stop the run, press Ctrl-C.

Each run of the script has a name.  The default name is
`matrix-<date>-<time>`, for example `matrix-20261119-1600`.  Because the
default name holds the start time, a new run does not overwrite the results
of an earlier run.  The script writes:

- `prof-results/<name>.log`, the output of every batch.
- `prof-results/<name>-results.csv`, one row for each complete test run.
- `prof-results/<name>-<batch>/<image>/`, the results of one batch.

`<batch>` is the name of the batch, and `<image>` is the tag of the image.

When a suite of a batch ends with an error, the script writes a `WARNING`
line to the log and continues with the next suite or the next batch.  The
script does not write a `WARNING` line for a failed test run.  The log marks
a test run without a complete result as `incomplete`, and
`<name>-results.csv` does not have a row for the incomplete test run.

To continue an interrupted run, pass the name of the run with `-r`.  Pass the
number of the first batch to repeat with `-b`.  Each `##### batch` line of
the log gives the number of a batch:

```
src/tests/multi-server/scripts/profiling/run_gperftools_capture_rate_matrix.sh -r matrix-20261119-1600 -b 25 -e 45
```

### Resource use dashboard

`run_gperftools_capture_rate_tests.sh` records the CPU and memory use of the
Docker VM and of every container, once per second, in
`<suite>-resource-usage.csv`.  Compare the runs on the Grafana dashboard,
which draws one line per run.

Start Grafana after the tests, so that Grafana does not add load to a run:

```
# Start Grafana, then open http://localhost:3000.
export RESULTS=$PWD/prof-results/capture-rate/$(git rev-parse --short HEAD)
docker compose -f src/tests/multi-server/scripts/profiling/grafana/docker-compose.yml up -d

# Stop Grafana.
docker compose -p capture-rate down
```

Select the suite and the container at the top of the dashboard.  The idle
runs are blue and the stress runs are orange.  A table lists `window_s`,
`samples`, and `capture_pct` for each run of the suite.

The graphs show the first 2 minutes 10 seconds of each run.  To show 6
minutes for the `5min` test, click the '5min (6 min)' link at the top right
of the dashboard.  To show 2 minutes 10 seconds again, click the
'short_ci (2 min)' link.
