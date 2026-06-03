# cest-analyzer

Go rewrite of `analyze_profiling_results_cest.sh`. Compares Callgrind
cycle-estimate (CEst) cost across one or more profiling runs without
requiring QCachegrind or a working `callgrind_annotate --show=CEst`.

## Requirements

- Go 1.21 or later
- No external dependencies (stdlib only)

Install Go on macOS:

```bash
brew install go
```

## Layout

The analysis core is split from the per-target entry points so the same code
serves the CLI, WASI, and the browser:

```text
go/
├── internal/cest/        I/O-free core (formula, parser, reports)
│   ├── cest.go           CEst formula + categories
│   ├── parse.go          Parse(io.Reader, ...) and summary scan
│   ├── analyze.go        Candidate, PickMain, Analyze
│   └── report.go         text / comparison / markdown writers
├── cmd/cest-analyzer/    CLI: flags, os.Open/Glob, stdout (native + WASI)
└── web/                  browser target
    ├── wasm/main.go      syscall/js bridge (globalThis.analyzeCest)
    └── static/           index.html, app.js, style.css, wasm_exec.js, .wasm
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
entry point ([web/wasm/main.go](web/wasm/main.go)) that exposes a
`globalThis.analyzeCest(runs, patterns, topN)` function. The page reads the
uploaded `callgrind.out.*` files with the `FileReader` API and hands their
text in; the same `internal/cest` core does the analysis.

#### Build

```bash
cd scripts/profiling/go

# Build the module into the web assets directory
GOOS=js GOARCH=wasm go build -o web/static/cest-analyzer.wasm ./web/wasm

# Copy the JS glue shipped with Go. Its path inside GOROOT changed across
# Go releases (older: misc/wasm/; newer: lib/wasm/), so locate it first:
cp "$(find "$(go env GOROOT)" -name wasm_exec.js | head -1)" web/static/
```

After this, `web/static/` holds everything the page needs:

```text
web/static/
├── index.html
├── app.js
├── style.css
├── wasm_exec.js          (copied from GOROOT)
└── cest-analyzer.wasm    (built above)
```

#### Run

The page must be served over HTTP from the host, not opened as a `file://`
URL. `file://` fails for two reasons: the browser blocks the `fetch()` of the
`.wasm`, and `WebAssembly.instantiateStreaming` requires the response to carry
`Content-Type: application/wasm`, which only a server sets. Any static file
server works; pick one:

```bash
cd scripts/profiling/go/web/static

# Python 3 (sends Content-Type: application/wasm for .wasm files)
python3 -m http.server 8080

# …or Node, if you have it
npx serve -l 8080 .
```

Then open <http://localhost:8080> in a browser.

To reach it from another machine on the network, bind all interfaces and use
the host's IP:

```bash
python3 -m http.server 8080 --bind 0.0.0.0
# then browse to http://<host-ip>:8080 from the other machine
```

#### Use

In the page: pick one or more `callgrind.out.*` files, enter space-separated
patterns, and click **Analyze**. The console-style report renders inline and
the Markdown report is available via the download button. All selected files
are treated as one run; grouping into multiple labelled runs for comparison is
a small change in [web/static/app.js](web/static/app.js) (build several keys in
the `runs` object).

### Comparison

| | `wasip1` (CLI) | `js` (browser) |
|---|---|---|
| Entry point | `./cmd/cest-analyzer` | `./web/wasm` |
| File access | host FS via `--dir` | uploaded files via `FileReader` |
| Output | stdout / `--md` file | DOM + Markdown download |
| Runtime | wasmtime, wazero, Node 21+ | any browser |

## Usage

```
cest-analyzer [--md <file>] [--top N] -d <dir> [-d <dir> ...] <pat> [pat ...]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-d <dir>` | `.` | Profiling directory containing `callgrind.out.*` files. Repeatable. |
| `--top N` | `10` | Number of top functions to show per pattern. |
| `--md <file>` | _(none)_ | Also write a Markdown report to this file. |

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

With two or more directories a comparison footer shows percentage change
relative to the first directory (baseline).

## CEst formula

```
CEst = Ir + 10*(I1mr + D1mr + D1mw) + 100*(ILmr + DLmr + DLmw) + 10*(Bcm + Bim)
```

Requires the run to have been profiled with `--cache-sim=yes --branch-sim=yes`.
Only self (exclusive) cost is reported — inclusive cost is not computed.

## Customizing categories

Edit the `defaultCategories` slice near the top of `main.go`. Each entry is a
label and a case-insensitive Go regexp. The first matching category wins, so
list the most specific patterns first.
