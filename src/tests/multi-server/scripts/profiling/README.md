# Profiling scripts

## Load-generator stats in the results tree

Each profiling run's result directory carries the load-generator's own
counters next to the callgrind output (written by
start_valgrind_profiling.sh at the end of the run):

- `load-stats.csv`: the per-second stats CSV proto_load writes during the
  run, copied verbatim.
- `run-stats.json`: one-object summary of the run.
  - `loadgen`: the TEST_LOADGEN_* configuration (pps, duration,
    `max_requests` = expected packet count).
  - `completion`: exact totals from proto_load's completion log line.
    `logged: false` means the load never completed: the run is partial.
  - `final`: the last CSV row, i.e. cumulative totals at shutdown: `sent`,
    `received`, `rtt`/`rttvar` (nanoseconds), `times` (response-time
    buckets: <us, us, 10us, 100us, ms, 10ms, 100ms, s), `backlog`,
    `max_backlog`, `blocked`. `null` when the CSV was missing or empty.
  - `phases`: script timings in seconds (`startup_s`, `send_wait_s`,
    `shutdown_s`) and `shutdown_timed_out`.

`completion.logged` is the direct completeness check for a run (the log line
only appears when the generator reached `max_requests`): a partial run no
longer has to be inferred from total-CEst outlier ratios (see
cinfra-profiling-server docs/noise-floor.md). `final` totals come from the
CSV's last row, written on a 1s timer, and can lag the completion totals by
up to one second of traffic.

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
