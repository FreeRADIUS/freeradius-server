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
