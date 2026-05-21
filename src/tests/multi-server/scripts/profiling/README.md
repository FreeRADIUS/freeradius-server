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
