# CPU Cycle Utilization (CEst) Utility

Compares Callgrind cycle-estimate (CEst) cost across one or more profiling runs.

## CEst formula

```
CEst = Ir + 10*(I1mr + D1mr + D1mw) + 100*(ILmr + DLmr + DLmw) + 10*(Bcm + Bim)
```

Requires the run to have been profiled with `--cache-sim=yes --branch-sim=yes`.
Only self (exclusive) cost is reported — inclusive cost is not computed.

## Requirements

- Go 1.21 or later
- No external dependencies (stdlib only)

Install Go on macOS:

```bash
brew install go
```
Install Go on Ubuntu:
```
sudo apt update
sudo apt install golang-go
go version
```

## Layout

The analysis core is split from the per-target entry points so the same code
serves the CLI, WASI, and the browser:

```text
go/
├── internal/cest/        I/O-free core (formula, parser, reports)
│   ├── cest.go           Events counters, CEst formula, categories
│   ├── parse.go          Parse(io.Reader, ...) and summary scan
│   ├── analyze.go        Candidate, PickMain, Analyze, top-N helpers
│   ├── report.go         text / comparison / markdown writers
│   ├── compare.go        per-function CEst compare (lowest-CEst baseline, spread)
│   └── json.go           JSON report schema + writer
├── cmd/cest-analyzer/    CLI: flags, os.Open/Glob, stdout (native + WASI)
└── web/                  browser target (GOOS=js); all analysis is client-side
    ├── wasm/main.go      syscall/js bridge (globalThis.cestMatrix, cestReport,
    │                     cestRunCEst, cestRunDetail, cestCompare)
    ├── index.html        compare UI (heatmap / trends / divergence / per-run detail /
    │                     multi-run compare) with local-file and hosted-store run
    ├── app.js            sources; the store picker reads the store's manifest.json
    ├── style.css         (run list) and run-index-map.json (workflow run links).
    ├── config.json       hosted-store URL/label (deploy-configurable)
    ├── wasm_exec.js      Go JS glue (copied from GOROOT); .wasm built alongside
    └── archive/v1/       archived single-run / pattern UI (unmaintained)
```

`internal/cest` never imports `os`, `flag`, or `syscall/js`. Callers feed it
data through `io.Reader` / `Candidate` and read back plain structs, which is
what lets the browser build (no filesystem) reuse the parser unchanged.

## Build

```bash
cd scripts/profiling/go

# Native binary
go build -o cest-analyzer ./cmd/cest-analyzer

# Run without building
go run ./cmd/cest-analyzer -d <dir> <pattern>
```

## Cross-compilation

Set `GOOS` and `GOARCH` before building — no toolchain changes needed.

```bash
# Linux x86-64
GOOS=linux GOARCH=amd64 go build -o cest-analyzer-linux ./cmd/cest-analyzer

# Linux ARM64 (e.g. Graviton, Pi)
GOOS=linux GOARCH=arm64 go build -o cest-analyzer-arm64 ./cmd/cest-analyzer

# Windows
GOOS=windows GOARCH=amd64 go build -o cest-analyzer.exe ./cmd/cest-analyzer
```

## WebAssembly

There are two WASM targets, with different entry points.

### Option 1: WASI — CLI in a sandbox (`./cmd/cest-analyzer`)

Available in Go 1.21+. Preserves the file-I/O CLI semantics without code
changes; runs in any WASI runtime.

```bash
GOOS=wasip1 GOARCH=wasm go build -o cest-analyzer.wasm ./cmd/cest-analyzer

# Run with wasmtime (install: brew install wasmtime)
wasmtime --dir /path/to/prof-results \
    cest-analyzer.wasm \
    -d /path/to/prof-results prefix1
```

### Option 2: `GOOS=js` — browser app (`./web/wasm`)

The browser has no filesystem, so this target uses a separate `syscall/js`
entry point ([web/wasm/main.go](web/wasm/main.go)) that exposes these functions
on `globalThis`:

- `cestMatrix(runs, topN)` — a complete function×run matrix the v2 views
  render (pass `topN = 0` for all functions).
- `cestRunCEst(files, foldPaths?)` — one run's per-function CEst, parsed one run
  at a time so the v2 loader can show progress (the matrix/baseline are assembled
  in JS). The optional `foldPaths` argument carries the call paths to fold (see
  **Folding call paths** below); the UI passes whatever is typed in the **fold**
  box. Also returns a `paths` map (each function's root-first call paths from the
  raw context graph) that backs the hover **copy-path** popover.
- `cestRunDetail(files, foldPaths?)` — one run's full per-function table (CEst +
  the 9 raw counters) for the single-run detail view; `foldPaths` is applied the
  same way as for `cestRunCEst`.
- `cestCompare(runs)` — the per-function CEst comparison for the v2 compare view
  (2–3 ticked runs): lowest-CEst baseline, Δ% vs best, and spread. This calls the
  **same** `internal/cest.CompareCEst` as the CLI's `--compare`, so the browser
  and the terminal report identical compare numbers (the math lives only in Go).
- `cestReport(runs, topN, patterns?)` — the rich JSON report (all 9 counters)
  behind v2's per-run **Download JSON**.

The page gets each `callgrind.out.*` file's text — from a local pick via the
`FileReader` API, or fetched from the hosted prof-results store over HTTP — and
hands it in; the same `internal/cest` core does the analysis. Analysis is
entirely client-side; nothing is uploaded.

#### Build

```bash
cd scripts/profiling/go

# Build the syscall/js module into the web UI directory (it serves its own .wasm).
GOOS=js GOARCH=wasm go build -o web/cest-analyzer.wasm ./web/wasm

# Copy the JS glue shipped with Go into the UI. Its path inside GOROOT changed
# across Go releases (older: misc/wasm/; newer: lib/wasm/), so locate it first:
WASM_EXEC="$(find "$(go env GOROOT)" -name wasm_exec.js | head -1)"
cp "$WASM_EXEC" web/
```

After this, `web/` holds everything the page needs:

```text
web/
├── index.html            (compare UI)
├── app.js
├── style.css
├── config.json           (hosted-store URL/label, deploy-configurable)
├── wasm_exec.js          (copied from GOROOT)
└── cest-analyzer.wasm    (built above)
```

#### Run

The page must be served over HTTP from the host, not opened as a `file://`
URL. `file://` fails for two reasons: the browser blocks the `fetch()` of the
`.wasm`, and `WebAssembly.instantiateStreaming` requires the response to carry
`Content-Type: application/wasm`, which only a server sets. Any static file
server works; pick one:

The UI is self-contained, so serve the `web/` directory directly:

```bash
cd scripts/profiling/go/web

# Python 3 (sends Content-Type: application/wasm for .wasm files)
python3 -m http.server 8080

# …or Node, if you have it
npx serve -l 8080 .
```

Then open <http://localhost:8080/> in a browser.

To reach it from another machine on the network, bind all interfaces and use
the host's IP:

```bash
python3 -m http.server 8080 --bind 0.0.0.0
# then browse to http://<host-ip>:8080 from the other machine
```

#### Use

The browser UI analyzes entirely in the browser; nothing is uploaded (the Repo
source only *downloads* result files from the store). It compares many runs at
once, where **one run = one directory of `callgrind.out.*` files** (one test
directory in the prof-results tree).

- **Add runs** from one of two sources (toggle beside **+ Add runs**):
  - **Local files** — the directory picker. Pick a leaf test directory for one
    run, or a parent (a run# or the whole `<sha>` directory) to load every run
    beneath it; labels drop the shared path prefix (e.g. `4/accept/short_ci`,
    `5/accept/short_ci`). The **import filter** nested in the Local files toggle
    narrows a broad pick to only the folders whose path contains one of its
    space-separated terms (e.g. import just the `ldap` runs from a whole-`<sha>`
    pick); it is greyed out (disabled) when the Repo source is selected.
  - **Repo** — the hosted prof-results store (URL/label set in
    [web/config.json](web/config.json)). Opens a picker that reads the
    store's `manifest.json` and lists every analyzable run — one row per
    `<branch>/<sha>/<run>/<suite>/<test>` leaf holding `callgrind.out.*` files
    (archived trees are skipped). Tick any number of runs (the header checkbox
    selects/clears all shown), optionally narrow with the search box (matches
    branch / sha / run / suite / test / workflow run number), and click any
    column header to sort (date, sha, branch, run, suite, test, by/PR).
    **Add selected** fetches those runs' `callgrind.out.*` files over HTTP and
    loads them, labelled `<sha>/<run>/<suite>/<test>`. The **by / PR** column
    links to the GitHub workflow run that produced each result, joined from the
    store's `run-index-map.json` ledger (`—` for runs published before the
    ledger existed).
- **Baseline = a run you choose.** By default it follows the column order: the
  **oldest** run when ordering by date (the default order), otherwise the first
  loaded run. Click **set base** on any chip to pin a specific run (a pinned
  choice stops following the default until you clear the runs). There is no
  mean/median baseline: for change-over-time you compare against a real reference
  run. With a single run loaded there is no baseline at all (see the Heatmap
  cost view).
- Three views (toggle top-left):
  - **Heatmap** — has two modes by run count:
    - **One run — cost view.** Functions ranked by self-CEst, most expensive on
      top, coloured on a heat ramp so you see where the cycles go within the run.
      Both ramp ends are configurable in the legend (worst end and cheapest end,
      default dark red → white); the ramp blends worst → orange → green →
      cheapest. The scale is **log-spread** over the displayed functions' CEst
      range, so the full ramp shows even when one function dominates the run
      (a linear scale would leave everything but the top hotspot near the cold
      end and the orange/green midtones unused). Click any column header
      (function, CEst, % of run) to re-sort; click again to flip the direction.
    - **Two or more runs — change view.** The function×run matrix, cells coloured
      by Δ% vs the chosen baseline run (green = improvement, red = regression).
      The baseline column is marked with a **base** label above its header and
      shows each function's reference CEst (M); the other columns show the Δ. A
      **date** row under the headers shows each run's date (local runs use the
      callgrind file's mtime, store runs the manifest date). Columns are ordered
      **by date by default** - oldest leftmost, newest rightmost, so they read as
      a timeline; the overflow menu's **Column order** can switch to load order or
      by CEst.
      The legend carries two adjustable **highlight thresholds**, one per
      direction: a cell highlights red only when `Δ ≥` the regression threshold,
      green only when `Δ ≤ −` the improvement threshold; smaller changes stay
      blank, so you set how much divergence in each direction is worth the eye.
  - **Trends** — a line chart over the runs in load order; the total-CEst line
    is always drawn, and you can pick up to 5 functions to overlay.
  - **Divergence** — a diverging bar chart of each function's change in
    **self-share** of total CEst (percentage points) for a current run vs a
    reference run (the baseline run by default, or any run you choose).
- **Per-run detail** — click a run's chip (or its heatmap column header) to leave
  the comparison views for that one run's full per-function table: every function
  with CEst plus the 9 raw Callgrind counters it is built from, sortable on any
  column and narrowed by the **patterns** filter. A second table sums the counters
  of every function matching each pattern term (one row per term). **← Back**, or
  any comparison-view button, returns.
- **Run chips** — each loaded run shows as a chip with a bar of its total CEst
  relative to the largest run; the baseline chip is marked and carries a **set
  base** button to make any other run the baseline, and **×** removes a run
  (**Clear** removes all).
- **Value mode** (multi-run heatmap / trends): Δ% vs baseline, CEst cycles, or
  CEst % of run total.
- Other controls: a **patterns** filter (space-separated, case-insensitive
  substrings), a **fold** box that folds a call path's self-CEst up into its
  caller (see **Folding call paths** below; folding re-parses every run, so it
  applies only when you press Enter in the box or click **Fold**, not on every
  keystroke; the paths baked into the current view stay listed under the run
  chips with a **reset fold list** button to clear them), the **functions**
  top-N count, and an overflow menu for column order (load order / by CEst /
  by date) and **Download JSON** (the full comparison dataset, all functions,
  every run, independent of the current view).

### Folding call paths

`--separate-callers=N` (set in the profiling step) makes Callgrind keep each
function's cost split by the chain of callers above it, written on disk as
`base'caller1'caller2'…` (nearest caller first). The parser aggregates that
back to one row per base function for every view, so the extra detail is
invisible by default, but it retains the per-context self-cost and the
caller→callee call graph. That retained detail is what lets the analyzer fold a
**specific call path** (not every call of a function) into its caller.

Folding removes the named frame and rolls its self-CEst up into whatever called
it. Because the cost is caller-separated, only the path you name is moved: if
`_talloc` is reached from two different places, folding `app_handler/talloc_pool/_talloc`
moves only the cost under that one path and leaves the other site alone. When a
folded frame has several callers, its self-cost is split across them by the
per-edge inclusive cost. Total self-CEst is preserved (cost that cannot reach an
unfolded ancestor, e.g. a folded root, is dropped).

A path is written **root-first, slash-separated, with the frame to fold last**;
comma-separate multiple paths. A single-element path folds every call of that
function. Folding needs profiling data captured with `--separate-callers`; on
data without it a multi-element path has nothing to match and folds nothing.

To avoid typing paths by hand, **hover a function name** in the Heatmap or the
per-run detail view: a small popover lists that node's call paths (most costly
first, from the `--separate-callers` data) plus an "all calls" entry. Click one
to copy it to the clipboard, then paste into the fold box. (Copy needs a click,
so hovering only reveals the choices.)

### Comparison

| | `wasip1` (CLI) | `js` (browser) |
|---|---|---|
| Entry point | `./cmd/cest-analyzer` | `./web/wasm` |
| File access | host FS via `--dir` | local pick (`FileReader`) or hosted store (HTTP fetch) |
| Output | stdout / `--md` / `--json` files (incl. `--compare`) | heatmap / trends / divergence / per-run detail / multi-run compare + JSON download |
| Runtime | wasmtime, wazero, Node 21+ | any browser |

## Usage

```
# Pattern report (per-pattern self-CEst, top-N per pattern, baseline = first -d)
cest-analyzer [--md <file>] [--json <file>] [--top N] -d <dir> [-d <dir> ...] <pat> [pat ...]

# Compare mode (per-function CEst across runs; the terminal/WASI equivalent of
# the UI compare view) - needs >=2 dirs; --filter scopes it to matching functions
cest-analyzer --compare [--filter pat,...] [--json <file>] -d <dir> -d <dir> [-d <dir> ...]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-d <dir>` | `.` | Profiling directory containing `callgrind.out.*` files. Repeatable. |
| `--compare` | off | Per-function CEst comparison across the `-d` runs (matches the UI compare view). Needs ≥2 dirs. |
| `--filter <pat,...>` | _(none)_ | `--compare` only: scope to functions whose name matches any filter (repeatable and/or comma-separated; substring, case-insensitive). Trailing positionals work too. |
| `--fold <path>` | _(none)_ | Fold a call path's self-CEst up into its caller (see **Folding call paths**). Root-first, slash-separated, frame to fold last (e.g. `app_handler/talloc_pool/_talloc`); repeatable and/or comma-separated for several paths. Needs `--separate-callers` profiling data. Applies to both the pattern report and `--compare`. |
| `--top N` | `10` | Number of top functions to show per pattern. Not used by `--compare`. |
| `--md <file>` | _(none)_ | Also write a Markdown report to this file. Not used by `--compare`. |
| `--json <file>` | _(none)_ | Also write a JSON report to this file. With `--compare`, writes the compare-shaped JSON (`cest-compare-1`); otherwise the per-run report (see Output). |

Patterns are case-insensitive substrings matched against function names.

### Examples

```bash
# Single run, two patterns
./cest-analyzer -d /path/to/prof-results prefix1 prefix2

# Pattern report comparing two runs, with a markdown file (per-pattern % vs dir 0)
./cest-analyzer \
    -d /path/to/build1/prof-results \
    -d /path/to/build2/prof-results \
    --md report.md --top 6 \
    prefix1 prefix2

# Compare mode: per-function CEst across runs, like selecting run chips in the UI.
# Diffs are measured against each function's lowest-CEst run; a "spread" column
# gives worst / best - 1, sorted spread-descending. --json writes the same data
# the UI's compare "Download JSON" produces.
./cest-analyzer --compare \
    -d /path/to/build1/prof-results \
    -d /path/to/build2/prof-results \
    --json compare.json

# Compare mode scoped to specific functions via --filter (repeatable and/or
# comma-separated), like typing in the UI's patterns field.
./cest-analyzer --compare \
    -d /path/to/build1/prof-results \
    -d /path/to/build2/prof-results \
    --filter _talloc,fr_rb --json compare.json

# Fold one call path's self-CEst up into its caller (needs --separate-callers
# profiling data). Here _talloc called via app_handler -> talloc_pool is folded
# into talloc_pool; _talloc reached any other way keeps its own row.
./cest-analyzer \
    -d /path/to/prof-results \
    --fold app_handler/talloc_pool/_talloc
```

The two forms answer different questions: the **pattern report** baselines every
run against the first `-d` and groups by your patterns; **`--compare`** is the
per-function, lowest-CEst-baselined matrix the UI shows when you tick run chips.
Both run identically under WASI (same binary).

## Output

For each directory the tool prints:

- Total CEst for the run
- Per-pattern self-CEst sum and percentage of total
- Top-N functions matching each pattern, sorted by self-CEst
- Whole-program category breakdown (memset, malloc, crypto, etc.)
- A component breakdown listing the 9 raw counters CEst is built from (Ir,
  I1mr, D1mr, D1mw, ILmr, DLmr, DLmw, Bcm, Bim) plus CEst, for the run total,
  each pattern, and each category

With two or more directories a comparison footer shows percentage change
relative to the first directory (baseline).

### JSON report (`--json`)

`--json <file>` writes a structured report. Every counter is reported as
`{ "number": <int>, "percent": <float> }`, where `percent` is the value's share
of the run's grand total for that same counter (so `Ir.percent` is the share of
total Ir, `D1mr.percent` the share of total D1mr, and so on). Per run it carries
the total CEst, a flat top-N `functions` list (matching any requested pattern,
or all functions if none were given), and the per-pattern and per-category
subtotals; each `functions` / `patterns` / `categories` row carries CEst plus
all 9 components. Multiple `-d` directories appear as elements of `runs`. The
same structure backs the **Tables** and **JSON** views in the web UI.

## Customizing categories

Edit the `DefaultCategories` function in
[internal/cest/cest.go](internal/cest/cest.go). Each entry is a label and a
case-insensitive Go regexp. The first matching category wins, so list the most
specific patterns first.
