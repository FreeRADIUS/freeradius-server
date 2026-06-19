# CPU Cycle Utilization (CEst) Utility

Compares Callgrind cycle-estimate (CEst) cost across one or more profiling runs.

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
│   └── json.go           JSON report schema + writer
├── cmd/cest-analyzer/    CLI: flags, os.Open/Glob, stdout (native + WASI)
└── web/                  browser target (GOOS=js); all analysis is client-side
    ├── wasm/main.go      syscall/js bridge (globalThis.analyzeCest, cestMatrix, cestReport)
    ├── v1/               single-run / pattern UI: index.html, app.js, style.css, wasm_exec.js, .wasm
    └── v2/               multi-run compare UI (heatmap / trends / divergence / per-run detail)
                          with local-file and hosted-store run sources; the store picker reads
                          the store's manifest.json (run list) and run-index-map.json (workflow
                          run links). Files: index.html, app.js, style.css, config.json,
                          wasm_exec.js, .wasm
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
entry point ([web/wasm/main.go](web/wasm/main.go)) that exposes three functions
on `globalThis`:

- `analyzeCest(runs, patterns, topN)` — pattern-centric, per-run top-N report
  (the v1 UI).
- `cestMatrix(runs, topN)` — a complete function×run matrix the v2 compare UI
  renders (pass `topN = 0` for all functions).
- `cestReport(runs, topN, patterns?)` — the rich JSON report (all 9 counters)
  behind v2's **Download JSON**.

The page gets each `callgrind.out.*` file's text — from a local pick via the
`FileReader` API, or fetched from the hosted prof-results store over HTTP — and
hands it in; the same `internal/cest` core does the analysis. Analysis is
entirely client-side; nothing is uploaded.

#### Build

```bash
cd scripts/profiling/go

# Build the same module into each UI directory. The two UIs are self-contained
# (each serves its own .wasm), so v2 can be served on its own without v1.
GOOS=js GOARCH=wasm go build -o web/v1/cest-analyzer.wasm ./web/wasm
GOOS=js GOARCH=wasm go build -o web/v2/cest-analyzer.wasm ./web/wasm

# Copy the JS glue shipped with Go into each UI. Its path inside GOROOT changed
# across Go releases (older: misc/wasm/; newer: lib/wasm/), so locate it first:
WASM_EXEC="$(find "$(go env GOROOT)" -name wasm_exec.js | head -1)"
cp "$WASM_EXEC" web/v1/
cp "$WASM_EXEC" web/v2/
```

After this, each UI directory holds everything its page needs, e.g. `web/v2/`:

```text
web/v2/
├── index.html            (v2 multi-run compare UI)
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

Each UI is self-contained, so you can serve a single UI directory directly (e.g.
`web/v2`). Serving the parent `web/` keeps both `/v1/` and `/v2/` reachable:

```bash
cd scripts/profiling/go/web

# Python 3 (sends Content-Type: application/wasm for .wasm files)
python3 -m http.server 8080

# …or Node, if you have it
npx serve -l 8080 .
```

Then open <http://localhost:8080/v1/> (single-run / pattern UI) or
<http://localhost:8080/v2/> (multi-run compare UI) in a browser.

To reach it from another machine on the network, bind all interfaces and use
the host's IP:

```bash
python3 -m http.server 8080 --bind 0.0.0.0
# then browse to http://<host-ip>:8080 from the other machine
```

#### Use

There are two browser UIs. Both analyze entirely in the browser; nothing is
uploaded (the Repo source only *downloads* result files from the store).

##### v1 — single-run / pattern UI (`/v1/`)

For each run pick its `callgrind.out.*` files (use **+ Add run** to compare
several labelled runs; the first is the baseline), enter space-separated
patterns, and click **Analyze**. The output has three tabs:

- **Report** — the console-style text report, including the component breakdown.
- **Tables** — a metric selector (CEst, each of the 9 components, or "All
  components") that re-renders the functions / patterns / categories tables for
  the chosen counter across runs.
- **JSON** — the JSON report exactly as `--json` writes it.

The Markdown and JSON reports are also available via the download buttons.

##### v2 — multi-run compare UI (`/v2/`)

Compares many runs at once, where **one run = one directory of
`callgrind.out.*` files** (one test directory in the prof-results tree).

- **Add runs** from one of two sources (toggle beside **+ Add runs**):
  - **Local files** — the directory picker. Pick a leaf test directory for one
    run, or a parent (a run# or the whole `<sha>` directory) to load every run
    beneath it; labels drop the shared path prefix (e.g. `4/accept/short_ci`,
    `5/accept/short_ci`). The **import filter** nested in the Local files toggle
    narrows a broad pick to only the folders whose path contains one of its
    space-separated terms (e.g. import just the `ldap` runs from a whole-`<sha>`
    pick); it is greyed out (disabled) when the Repo source is selected.
  - **Repo** — the hosted prof-results store (URL/label set in
    [web/v2/config.json](web/v2/config.json)). Opens a picker that reads the
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
- **Baseline = the median (p50) run** by total CEst (lower-middle for an even
  count). It is an actual profile, not a synthetic average, and is recomputed
  whenever the selected run set changes.
- Three views (toggle top-left):
  - **Heatmap** — the function×run matrix; cells are coloured by Δ% vs the p50
    baseline (green = improvement, red = regression) and outlined when
    `|Δ|` ≥ the flag threshold.
  - **Trends** — a line chart over the runs in load order; the total-CEst line
    is always drawn, and you can pick up to 5 functions to overlay.
  - **Divergence** — a diverging bar chart of each function's change in
    **self-share** of total CEst (percentage points) for a current run vs a
    reference run (the p50 baseline by default, or any run you choose).
- **Per-run detail** — click a run's chip (or its heatmap column header) to leave
  the comparison views for that one run's full per-function table: every function
  with CEst plus the 9 raw Callgrind counters it is built from, sortable on any
  column and narrowed by the **patterns** filter. A second table sums the counters
  of every function matching each pattern term (one row per term). **← Back**, or
  any comparison-view button, returns.
- **Run chips** — each loaded run shows as a chip with a bar of its total CEst
  relative to the largest run; the p50 baseline chip is marked, and **×** removes
  a run (**Clear** removes all).
- **Value mode** (heatmap / trends): Δ% vs p50, Δ% vs that run's total, CEst
  cycles, or CEst % of run total.
- Other controls: a **patterns** filter (space-separated, case-insensitive
  substrings), the **functions** top-N count, the flag **threshold**, and an
  overflow menu for column order (load order / by CEst) and **Download JSON**
  (the full comparison dataset — all functions, every run — independent of the
  current view).

### Comparison

| | `wasip1` (CLI) | `js` (browser) |
|---|---|---|
| Entry point | `./cmd/cest-analyzer` | `./web/wasm` |
| File access | host FS via `--dir` | local pick (`FileReader`) or hosted store (HTTP fetch) |
| Output | stdout / `--md` / `--json` files | v1: Report / Tables / JSON tabs + downloads · v2: heatmap / trends / divergence + JSON download |
| Runtime | wasmtime, wazero, Node 21+ | any browser |

## Usage

```
cest-analyzer [--md <file>] [--json <file>] [--top N] -d <dir> [-d <dir> ...] <pat> [pat ...]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-d <dir>` | `.` | Profiling directory containing `callgrind.out.*` files. Repeatable. |
| `--top N` | `10` | Number of top functions to show per pattern. |
| `--md <file>` | _(none)_ | Also write a Markdown report to this file. |
| `--json <file>` | _(none)_ | Also write a JSON report to this file (see Output). |

Patterns are case-insensitive substrings matched against function names.

### Examples

```bash
# Single run, two patterns
./cest-analyzer -d /path/to/prof-results prefix1 prefix2

# Compare two runs, write markdown report
./cest-analyzer \
    -d /path/to/build1/prof-results \
    -d /path/to/build2/prof-results \
    --md report.md --top 6 \
    prefix1 prefix2
```

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

## CEst formula

```
CEst = Ir + 10*(I1mr + D1mr + D1mw) + 100*(ILmr + DLmr + DLmw) + 10*(Bcm + Bim)
```

Requires the run to have been profiled with `--cache-sim=yes --branch-sim=yes`.
Only self (exclusive) cost is reported — inclusive cost is not computed.

## Customizing categories

Edit the `DefaultCategories` function in
[internal/cest/cest.go](internal/cest/cest.go). Each entry is a label and a
case-insensitive Go regexp. The first matching category wins, so list the most
specific patterns first.
