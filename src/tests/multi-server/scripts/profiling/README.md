## generate_callgrind_report.py

python3 src/tests/multi-server/scripts/profiling/generate_callgrind_report.py \
  <results_dir> \
  --title "FreeRADIUS accept 5min" \
  --text-output valgrind_report_radenv_prof_accept.txt \
  --md-output valgrind_report_radenv_prof_accept.md

## Generate text based report from Valgrind/Callgrind results
callgrind_annotate $(find . -name "callgrind.out.*" -size +0c | sort) > callgrind_report.txt

## Generate SVG sharable file of valgrind/callgrind results

Dependency: ```brew install gprof2dot```

Generate SVG file for one worker thread:
```
gprof2dot --format=callgrind \
  <path-to-prof-results>/callgrind.out.1004-04 \
  | dot -Tsvg -o callgraph_thread04.svg
```

Generate SVG file per worker thread:
```
for f in <path-to-prof-results>/callgrind.out.1004-{04..12}; do
  thread=$(grep "^thread:" "$f" | awk '{print $2}')
  gprof2dot --format=callgrind "$f" \
    | dot -Tsvg -o "callgraph_thread${thread}.svg"
done
```

## gperftools results

`start_gperftools_profiling.sh` converts the raw profile in the container,
where the build that the sample addresses belong to still exists.  To repeat
the conversion by hand, run these commands from a container that holds the same
build.  `PPROF_BINARY_PATH` points pprof at the shared objects
(`libfreeradius-*.so` and `rlm_*.so` install into `/usr/lib`).
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
