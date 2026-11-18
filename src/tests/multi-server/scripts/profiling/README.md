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
