// app.js — CEst compare UI (v2).
//
// Loads the WASM core (cest-analyzer.wasm, alongside this file) and calls the
// cestMatrix(runs, topN) bridge to get a complete function×run matrix, then
// renders the comparison views. Phase 1: local directory loading + the heatmap
// view (cost ranking for one run; Δ% vs a chosen baseline run for many). Trends and
// divergence views are added next.
//
// A "run" is one directory of callgrind.out.* files (one test directory in the
// prof-results tree). Everything runs locally in the browser; no file is sent.

"use strict";

const $ = (id) => document.getElementById(id);

const addRunsBtn = $("add-runs");
const clearBtn   = $("clear-runs");
const dirInput   = $("dir-input");
const importFilterInput = $("import-filter");
const chipsEl     = $("chips");
const emptyHint  = $("empty-hint");
const controlsEl = $("controls");
const viewseg    = $("viewseg");
const valseg     = $("valseg");
const topnInput  = $("topn");
const focusRunSel = $("focusrun");
const focusRunLbl = $("focusrun-lbl");
const patternsInput = $("patterns");
const foldInput = $("fold");
const foldApplyBtn = $("fold-apply");
// Fold call paths the user entered: comma-separated "root/.../target" paths
// (each path uses "/", so commas separate paths). Folded in the Go core per run.
function foldPaths() {
  if (!foldInput) return [];
  return foldInput.value.split(",").map((s) => s.trim()).filter(Boolean);
}
// The fold paths actually baked into the current matrix (set by parseRuns from
// the box at parse time). Rendered persistently under the chips so it stays
// clear which folds the displayed numbers reflect, even after editing the box.
let appliedFoldPaths = [];
const menuBtn    = $("menu-btn");
const menu       = $("menu");
const nviewEl     = $("nview");
const nlegendEl  = $("nlegend");
const errorP     = $("error");
const nrunCount  = $("nrun-count");
const nrunBase   = $("nrun-base");
const loadbar    = $("loadbar");
const loadbarMsg = $("loadbar-msg");
const loadbarFill = $("loadbar-fill");
const loadphase  = $("loadphase");
const foldList   = $("foldlist");
const foldCtl    = $("fold-ctl");
const appliedFoldEl = $("appliedfold");

// ---- state ---------------------------------------------------------------
let runs = [];          // [{ label, files: { name: text } }] in load order
let full = null;        // cached ALL-functions matrix from one parse of the runs
let matrix = null;      // `full` sliced to the displayed function count
let view = "heat";      // 'heat' | 'trend' | 'diverge'
let valMode = "delta";  // 'delta' (Δ% vs baseline) | 'abs' (CEst cycles)
// Heatmap column order. Default 'date': oldest run leftmost → newest rightmost,
// so the columns read as a timeline. 'load' | 'cest' | 'date'.
let orderMode = "date";
// Baseline run for the multi-run change views: a user-chosen run (default the
// first loaded run), NOT a p50 median. Δ% is measured against it. With a single
// run loaded the heatmap is instead a cost view (see renderHeatCost).
let baseRun = 0;        // baseline run index, in load order
// When ≥2 runs are loaded the heatmap is the change view, but the user can focus
// one run to see its single-run cost heatmap. costRun = that run's index, or null
// for the all-runs change view.
let costRun = null;
// Until the user explicitly clicks "set base", the baseline follows a default:
// the oldest run when ordering by date, else the first loaded run.
let baseRunPinned = false;
// Single-run cost heatmap ramp ends, both configurable from the legend: hotColor
// is the worst (most expensive) end, bestColor the cheapest end. The ramp runs
// bestColor → green → orange → hotColor; the scale is log-spread (see
// renderHeatCost) so the full ramp shows even when one function dominates.
let hotColor = "#b42318";
let bestColor = "#ffffff";
// Single-run cost heatmap column sort (click a header to flip). Default: most
// expensive on top.
let costSort = { key: "cest", dir: "desc" }; // key: 'name' | 'cest' | 'pct'
// Heatmap highlight thresholds, set separately per direction from the legend: a
// cell highlights red only when Δ% vs baseline ≥ regressMin (regression), or
// green only when Δ% ≤ −improveMin (improvement). Smaller changes stay blank.
let regressMin = 15;
let improveMin = 10;
let wasmReady = false;

// trends view: which function indices to plot (null = default top regressors,
// max 5). divergence view: the current run, the comparison reference, and how
// many functions to show. Reset when the run set changes (see analyze()).
let trendFns = null;
let curRun = "base";    // divergence current run: 'base' (baseline) or a run index
let cmpRun = null;      // divergence reference: null (most recent by date), 'base' (baseline), or a run index
let dvgTopN = 10;       // divergence: 10 | 25 | 'all'
let lastPatternsKey = ""; // last applied patterns string, to know when to reset trend picks
const TREND_COLORS = ["#b42318", "#1f5fbf", "#b45309", "#6d28d9", "#0e7490"];

// detail view: when a run chip is clicked we leave the comparison views and show
// one run's full per-function breakdown (all 9 raw counters + CEst). detailRun is
// that run's index (null = comparison views). detailData caches the parsed run so
// re-sorting / re-filtering needs no re-parse. The function table and the pattern
// table each keep their own {key,dir} sort. Detail is exited (set to null) on any
// run-set change (see parseRuns) and when a comparison view button is clicked.
let detailRun = null;     // run index shown in detail, or null
let detailData = null;    // { formula, total, functions:[{name,Ir,...,CEst}] } for detailRun
let detailFnSort = { key: "CEst", dir: "desc" };  // function table sort
let detailPatSort = { key: "CEst", dir: "desc" }; // pattern table sort

// compare view: up to COMPARE_MAX runs selected (chip checkbox / Ctrl-click, or
// heatmap header Ctrl-click) for a side-by-side per-function CEst table.
// compareSel is the staged selection (in click order); compareRuns is the set
// currently shown (null = not in the compare view). Diffs are measured against
// each function's lowest-CEst run among the selected. Both reset on a run-set
// change (see parseRuns).
const COMPARE_MAX = 3;
let compareSel = [];
let compareRuns = null;
let compareSort = { key: "spread", dir: "desc" }; // 'name' | 'spread' | a run index
let compareTopN = "all"; // compare view row cap: 'all' (default) or a number
let compareData = null;   // Go-computed compare rows (cestCompare) for compareDataKey
// True while restoreFromURL() is reconstructing state from a shared link, so
// render()'s syncURL() doesn't overwrite the hash mid-restore (see syncURL).
let restoring = false;
let compareDataKey = "";  // the compareRuns the cached rows were computed for
// The 10 numeric columns shared by both detail tables (first column is the
// Function/Pattern name). CEst leads, then the 9 raw Callgrind counters.
const COUNTER_COLS = ["CEst", "Ir", "I1mr", "D1mr", "D1mw", "ILmr", "DLmr", "DLmw", "Bcm", "Bim"];
const COUNTER_DESC = {
  CEst: "CPU Cycle Estimate",
  Ir:   "Instruction Fetch",
  I1mr: "L1 Instr. Fetch Miss",
  D1mr: "L1 Data Read Miss",
  D1mw: "L1 Data Write Miss",
  ILmr: "LL Instr. Fetch Miss",
  DLmr: "LL Data Read Miss",
  DLmw: "LL Data Write Miss",
  Bcm:  "Mispredicted Cond. Branch",
  Bim:  "Mispredicted Ind. Branch",
};

// ---- WASM load -----------------------------------------------------------
async function loadWasm() {
  const go = new Go(); // from wasm_exec.js (same directory)
  const resp = await fetch("cest-analyzer.wasm");
  const { instance } = await WebAssembly.instantiateStreaming(resp, go.importObject);
  go.run(instance); // registers globalThis.cestMatrix, then blocks on select{}
  wasmReady = true;
}
const wasmReadyP = loadWasm().catch((e) => showError(`Failed to load WASM: ${e}`));

// ---- store config --------------------------------------------------------
// The hosted prof-results store URL/label is deploy-configurable via config.json
// (fetched at startup) so testdev/prod/vanity hosts don't need a rebuild. The
// Go/WASM core never sees this — it's used only by the hosted-store picker UI
// (and, later, for fetching runs from the store).
const DEFAULT_STORE = { url: "https://cinfra-ca.testdev.inkbridge.io/profiling", label: "cinfra-ca.testdev.inkbridge.io" };
const store = { ...DEFAULT_STORE };

// Hosted-store picker state. storeRuns is the manifest's analyzable runs, each
// re-parsed from its path (see parsePathParts) so archived/non-standard trees
// are filtered out. storeLedger maps a store run back to the GitHub workflow
// run that produced it (run-index-map.json), for the "by / PR" column.
let storeRuns = [];        // [{ path, date, bytes, branch, sha, run, suite, test, cgFiles:[name] }]
let storeLedger = {};      // "branch sha run suite test" -> { number, runId, repo }
let repoTicked = new Set(); // ticked run paths
let repoShown = [];         // runs currently visible under the search filter (for select-all)
let repoSort = { key: "date", dir: "desc" }; // picker column sort (newest first by default)
async function loadConfig() {
  try {
    const resp = await fetch("config.json", { cache: "no-store" });
    if (resp.ok) {
      const cfg = await resp.json();
      if (cfg && cfg.store) {
        if (cfg.store.url) store.url = cfg.store.url;
        if (cfg.store.label) store.label = cfg.store.label;
      }
    }
  } catch (e) { /* config.json absent/unreachable — keep defaults */ }
  if (!store.label && store.url) {
    try { store.label = new URL(store.url).host; } catch (e) { /* leave as-is */ }
  }
  const hostEl = $("repo-host"); if (hostEl) hostEl.textContent = store.label;
  const urlEl = $("repo-url"); if (urlEl) urlEl.textContent = store.url.replace(/^https?:\/\//, "");
}
const configReadyP = loadConfig();

// ---- loading indicator ---------------------------------------------------
// Adding one run is instant, but reading + parsing 10–20 runs takes long enough
// that the UI looks stuck. showLoading paints a status bar before the work runs.
// frac (0..1) shows determinate progress (the file-reading phase, which is async
// and animates); pass null for the indeterminate sweep (the analyze phase, a
// short blocking WASM parse — the bar is painted first, then the parse runs).
// The Add/Clear buttons are disabled while the bar is up to block re-entry.
function showLoading(msg, frac) {
  loadbarMsg.textContent = msg;
  if (frac == null) {
    loadbar.classList.add("indet");
    loadbarFill.style.width = "100%";
  } else {
    loadbar.classList.remove("indet");
    loadbarFill.style.width = Math.round(Math.max(0, Math.min(1, frac)) * 100) + "%";
  }
  loadbar.hidden = false;
  addRunsBtn.disabled = true;
  clearBtn.disabled = true;
}
function hideLoading() {
  loadbar.hidden = true;
  loadbar.classList.remove("indet");
  hidePhases();
  addRunsBtn.disabled = false;
  clearBtn.disabled = false;
}
// Phase stepper (above the bar): names the high-level steps of the operation so
// it's clear reading files is the quick step and analysis is where time goes.
// setPhaseList renders the chips (all pending); setActivePhase highlights one,
// marks earlier ones done. Driven by the entry points, not parseRuns.
function setPhaseList(names) {
  loadphase.innerHTML = names.map((n, k) =>
    (k ? '<span class="lp-sep">→</span>' : "") +
    '<span class="lp-step"><i class="lp-dot"></i>' + esc(n) + "</span>"
  ).join("");
  loadphase.hidden = false;
}
function setActivePhase(idx) {
  loadphase.querySelectorAll(".lp-step").forEach((el, k) => {
    el.classList.toggle("done", k < idx);
    el.classList.toggle("active", k === idx);
  });
}
function hidePhases() {
  loadphase.hidden = true; loadphase.innerHTML = "";
  if (foldList) { foldList.hidden = true; foldList.innerHTML = ""; }
}
// setFoldList lists the full call paths being folded under the Folding pill (one
// row each). Empty paths => hidden (a length-1 path folds every call of that fn).
function setFoldList(paths) {
  if (!foldList) return;
  if (!paths.length) { foldList.hidden = true; foldList.innerHTML = ""; return; }
  foldList.innerHTML = paths.map((p) => '<span class="foldpath">' + esc(p) + "</span>").join("");
  foldList.hidden = false;
}
// yieldToPaint resolves after the browser has painted the current DOM, so a
// status bar shown just before a blocking synchronous call is actually visible
// (requestAnimationFrame runs before paint; the setTimeout defers past it).
function yieldToPaint() {
  return new Promise((resolve) => requestAnimationFrame(() => setTimeout(resolve, 0)));
}
// Above this many runs the analyze (parse) step is slow enough to warrant the
// indeterminate bar; below it the parse is instant and a bar would just flash.
const LOADING_MIN_RUNS = 4;

// ---- file loading --------------------------------------------------------
function readFileText(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(r.error);
    r.readAsText(file);
  });
}

// uniqueLabel suffixes "(2)", "(3)", ... when a folder name repeats.
function uniqueLabel(base) {
  const used = new Set(runs.map((r) => r.label));
  if (!used.has(base)) return base;
  for (let n = 2; ; n++) {
    const cand = `${base} (${n})`;
    if (!used.has(cand)) return cand;
  }
}

// addRunsFromPick ingests one directory pick. The picker returns every file
// under the chosen directory recursively, so a leaf test directory yields one
// run, while a parent (a run# — or the whole <sha> directory) yields many. The
// callgrind.out.* files are grouped by their containing directory; each such
// leaf directory becomes one run (matching the prof-results layout
// <sha>/<run#>/<suite>/<test>/callgrind.out.*). Labels drop the shared path
// prefix so a multi-run pick reads as "4/accept/short_ci", "5/accept/short_ci".
async function addRunsFromPick(fileList) {
  const cg = Array.from(fileList).filter((f) => f.name.indexOf("callgrind.out") === 0);
  if (cg.length === 0) {
    showError("No callgrind.out.* files found anywhere under that selection.");
    return;
  }
  // Group the callgrind files by their containing directory (dirname of the
  // path the picker reports relative to the chosen folder).
  const groups = new Map(); // dir -> [File]
  cg.forEach((f) => {
    const rel = f.webkitRelativePath || f.name;
    const dir = rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "";
    if (!groups.has(dir)) groups.set(dir, []);
    groups.get(dir).push(f);
  });

  // Optional import filter: keep only the directories whose path contains one
  // of the space-separated terms (case-insensitive). Empty => keep everything.
  // This lets a single broad pick (a whole <sha> tree of mixed suites) be
  // narrowed to, say, just the "ldap" suite directories.
  let dirs = Array.from(groups.keys());
  const importTerms = (importFilterInput ? importFilterInput.value : "")
    .trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (importTerms.length) {
    const kept = dirs.filter((d) => { const l = d.toLowerCase(); return importTerms.some((t) => l.includes(t)); });
    if (kept.length === 0) {
      showError('Import filter "' + importFilterInput.value.trim() + '" matched none of the '
        + dirs.length + " folder(s) in that selection.");
      return;
    }
    dirs = kept;
  }
  const prefix = commonPrefixSegs(dirs); // trimmed from labels when many runs share it

  // Reading callgrind files off disk is async, so the bar can show real per-run
  // progress. Only worth showing for a multi-run pick; one run is instant. The
  // reads often resolve within a single frame, so we yieldToPaint after each
  // progress update — otherwise the increments fold and the fill appears to
  // jump straight to the end. frac = runs completed / total (so "run 7 of 10"
  // shows at 60%: six done, reading the seventh). analyze() then owns the bar.
  const showReadProgress = dirs.length > 1;
  // The phase stepper appears when either phase will be slow enough to show the
  // bar. Reading is the quick step; analysis (the full re-parse of every run) is
  // the slow one — the stepper makes that explicit.
  const analyzeShowsBar = (runs.length + dirs.length) >= LOADING_MIN_RUNS;
  // showPhases drives the stepper AND forces the analyze bar (forceProg below).
  // Without forceProg, a sub-LOADING_MIN_RUNS pick leaves the stale "Reading run
  // N of N" bar at 100% under an active "Analyzing" pill (parseRuns paints no bar
  // below the threshold), which reads as a stuck transition.
  const showPhases = showReadProgress || analyzeShowsBar;
  if (showPhases) { setPhaseList(["Reading files", "Analyzing"]); setActivePhase(0); }
  for (let di = 0; di < dirs.length; di++) {
    const dir = dirs[di];
    if (showReadProgress) {
      // Fill matches the displayed run number so the bar tracks the counter.
      showLoading("Reading run " + (di + 1) + " of " + dirs.length + "…", (di + 1) / dirs.length);
      await yieldToPaint();
    }
    const segs = dir.split("/");
    const trimmed = segs.slice(prefix.length).join("/");
    const label = uniqueLabel(trimmed || segs[segs.length - 1] || `run ${runs.length + 1}`);
    const filesObj = {};
    const groupFiles = groups.get(dir);
    await Promise.all(groupFiles.map(async (f) => { filesObj[f.name] = await readFileText(f); }));
    // Date = newest callgrind file mtime (when the run finished), in epoch
    // seconds to match the store's manifest dates (see fmtStoreDate).
    const mtimeMs = groupFiles.reduce((m, f) => Math.max(m, f.lastModified || 0), 0);
    runs.push({ label, files: filesObj, date: mtimeMs ? Math.round(mtimeMs / 1000) : 0 });
  }
  if (showPhases) setActivePhase(1); // reading done → analyzing
  hideError();
  // forceProg: paint the analyze bar whenever the stepper is up (even below
  // LOADING_MIN_RUNS), so it replaces the reading bar rather than leaving it stale.
  await analyze({ forceProg: showPhases }); // parseRuns continues the bar with per-run analyze progress
}

// commonPrefixSegs returns the shared leading path segments across dirs, so
// labels can drop the redundant prefix (e.g. the <sha>) when one parent pick
// yields many runs. Returns [] for 0 or 1 dirs (nothing to trim).
function commonPrefixSegs(dirs) {
  if (dirs.length <= 1) return [];
  const split = dirs.map((d) => d.split("/"));
  const first = split[0];
  let k = 0;
  for (; k < first.length; k++) {
    const seg = first[k];
    if (!split.every((s) => s[k] === seg)) break;
  }
  return first.slice(0, k);
}

// ---- analysis (WASM) -----------------------------------------------------
// parseRuns parses every loaded run and caches the full function set (all
// functions, ordered by max CEst across runs). This is the expensive step, so
// it runs only when the run set changes, never on a function-count change.
//
// It parses ONE RUN AT A TIME (cestRunCEst) rather than all at once (cestMatrix)
// so the loading bar shows real per-run progress and the page stays responsive:
// each run's parse is a short synchronous chunk, and yieldToPaint between runs
// lets the browser paint the bar. The shared function set and the baseline run
// are then assembled in JS — the same result cestMatrix returns, just streamed.
// Returns true when a fresh full matrix is ready.
// verb labels the loading bar message ("Analyzing" / "Folding"); forceProg shows
// the bar even below LOADING_MIN_RUNS (folding is expensive at any run count, so
// it always wants feedback).
async function parseRuns(verb = "Analyzing", forceProg = false) {
  if (!wasmReady) { showError("WASM still loading — try again in a moment."); return false; }
  if (runs.length === 0) { full = null; matrix = null; render(); return false; }

  const R = [];                     // per run: { label, total, cest:{fn:CEst} }
  const maxC = Object.create(null); // per-function max CEst across runs (row order)
  const pathAcc = Object.create(null); // fn -> Map(path -> max CEst across runs)
  const showProg = forceProg || runs.length >= LOADING_MIN_RUNS;
  const fp = foldPaths();           // same for every run in this parse; record what was applied
  appliedFoldPaths = fp;
  // Per-run parse cache: a run's result (total / per-fn CEst / call paths) only
  // depends on its own files and the fold paths, never on the other runs. So we
  // cache it on the run object keyed by the fold state and reuse it. This makes
  // removing a run (the survivors are all hits) and any non-fold re-render
  // instant; only genuinely new runs, or a fold change, actually re-parse in
  // WASM (the expensive step: copy file text into Go, scan files, parse).
  const foldKey = fp.join("\n"); // paths are slash-separated, so newline is a safe join
  // Count cache misses so the progress bar reflects only the runs that parse.
  let toParse = 0;
  for (let i = 0; i < runs.length; i++) {
    if (!runs[i]._cache || runs[i]._cache.foldKey !== foldKey) toParse++;
  }
  let parsed = 0;
  let formula = "";
  for (let i = 0; i < runs.length; i++) {
    let res = runs[i]._cache;
    if (!res || res.foldKey !== foldKey) {
      if (showProg) {
        // Fill tracks runs actually parsed (cached ones are skipped instantly).
        parsed++;
        showLoading(verb + " run " + parsed + " of " + toParse + "…", parsed / toParse);
        await yieldToPaint(); // paint this increment before the run's blocking parse
      }
      const r = cestRunCEst(runs[i].files, fp);
      if (r.error) { showError(r.error); return false; }
      res = { foldKey, total: r.total, cest: r.cest, paths: r.paths, formula: r.formula };
      runs[i]._cache = res;
    }
    formula = res.formula || formula;
    const cest = res.cest;
    for (const name in cest) {
      const c = cest[name];
      if (c > (maxC[name] || 0)) maxC[name] = c;
    }
    // Union each run's per-function call paths, keeping the max CEst per path
    // (paths are structural and largely identical across runs of the same build).
    if (res.paths) {
      for (const fn in res.paths) {
        let m = pathAcc[fn]; if (!m) m = pathAcc[fn] = new Map();
        const list = res.paths[fn];
        for (let k = 0; k < list.length; k++) {
          const pc = list[k], prev = m.get(pc.p);
          if (prev === undefined || pc.c > prev) m.set(pc.p, pc.c);
        }
      }
    }
    R.push({ label: runs[i].label, total: res.total, cest, date: runs[i].date || 0 });
  }
  // Flatten the path union: per function, sorted by CEst descending, top 12.
  const pathsByFn = Object.create(null);
  for (const fn in pathAcc) {
    const arr = Array.from(pathAcc[fn], ([p, c]) => ({ p, c }));
    arr.sort((a, b) => (b.c - a.c) || (a.p < b.p ? -1 : a.p > b.p ? 1 : 0));
    pathsByFn[fn] = arr.length > 12 ? arr.slice(0, 12) : arr;
  }

  const totals = R.map((r) => r.total);
  // Baseline = the user-pinned run, else the default (oldest when ordering by
  // date, else first loaded); the p50 median is gone. Clamp + unpin if the run
  // set shrank below the previous pick.
  if (baseRun >= R.length || baseRun < 0) { baseRun = 0; baseRunPinned = false; }
  if (!baseRunPinned) baseRun = defaultBaseRun(R);
  if (costRun !== null && costRun >= R.length) costRun = null; // focused run gone
  const BASE = baseRun;
  const maxTotal = totals.reduce((m, t) => (t > m ? t : m), 1);

  // Shared function set: every function seen in any run, by max CEst descending
  // (name ascending as a tiebreaker), matching cestMatrix's row ordering.
  const funcs = Object.keys(maxC).sort((a, b) => (maxC[b] - maxC[a]) || (a < b ? -1 : a > b ? 1 : 0));

  full = { funcs, R, totals, BASE, maxTotal, pathsByFn };
  // The run set changed, so view selections keyed by run/function index reset.
  trendFns = null;
  curRun = "base";
  cmpRun = null;
  // The detail view's cached parse is keyed to a specific run index, so leave it
  // and fall back to the comparison views whenever the run set changes.
  detailRun = null;
  detailData = null;
  // Re-parse invalidates the cached compare rows so they recompute against the
  // new self-costs (e.g. after a fold change); the selection itself is kept,
  // and reset only when runs are removed/cleared (where indices change).
  compareData = null;
  compareDataKey = "";
  if ($("formula") && formula) $("formula").textContent = formula;
  return true;
}

// applyTopN re-slices the cached full matrix to the displayed function count.
// Cheap (no parsing), so it runs on every functions-count change.
function applyTopN() {
  if (!full) return;
  // Default to all functions; an empty / non-positive box means "no cap".
  const raw = parseInt(topnInput.value, 10);
  const topN = (isNaN(raw) || raw <= 0) ? Infinity : raw;
  // Optional patterns filter (space-separated, case-insensitive substring).
  // Empty => all functions. Filters the cached full set in JS (no re-parse),
  // preserving the max-CEst order, then keeps the top-N of the matches.
  const patKey = patternsInput.value.trim();
  const pats = patKey.toLowerCase().split(/\s+/).filter(Boolean);
  let funcs = full.funcs;
  if (pats.length) {
    funcs = funcs.filter((fn) => { const l = fn.toLowerCase(); return pats.some((p) => l.includes(p)); });
  }
  matrix = {
    funcs: funcs.slice(0, topN),
    R: full.R, totals: full.totals, BASE: full.BASE, maxTotal: full.maxTotal,
  };
  // Trend plots index into the displayed funcs. The index is stable when only
  // the count changes (prefix slice), but not when the filter changes the set —
  // so reset the picks on a patterns change; otherwise just drop overflow.
  if (patKey !== lastPatternsKey) { trendFns = null; lastPatternsKey = patKey; }
  else if (trendFns) {
    trendFns = trendFns.filter((f) => f < matrix.funcs.length);
    if (trendFns.length === 0) trendFns = null;
  }
  render();
}

// analyze re-parses (run set changed) then applies the current function count.
// parseRuns shows its own determinate per-run progress on the loading bar; the
// finally always clears the bar (including a reading-phase bar from addRunsFromPick).
async function analyze({ verb = "Analyzing", forceProg = false } = {}) {
  try {
    if (await parseRuns(verb, forceProg)) applyTopN();
  } finally {
    hideLoading();
  }
}

// ---- helpers (ported from the wireframe) ---------------------------------
// Millions, 1 decimal for normal values, but adaptive: when a value is so small
// that 1 decimal would round it to 0.0M, add decimals to keep a couple of
// significant figures so small-but-nonzero CEst shows a real digit instead of a
// misleading 0.0M. True zero stays 0.0M. (fmtM3 does the same with 3 decimals.)
const fmtM = (v) => {
  const m = v / 1e6;
  const abs = Math.abs(m);
  // abs < 0.05 is exactly where toFixed(1) rounds to 0.0.
  const dec = (abs > 0 && abs < 0.05) ? Math.min(12, 1 - Math.floor(Math.log10(abs))) : 1;
  return m.toFixed(dec) + "M";
};
// Millions for the compare table, where sub-0.1M CEst differences (e.g. two
// values that both round to 0.0M but differ by tens of percent) must stay
// legible. Adaptive precision: at least 3 decimals (matching the rest of the
// table), but more when the value is so small that 3 decimals would round it
// to 0.000M — enough to keep ~3 significant figures, so every nonzero cell
// shows a real digit instead of a misleading zero. True zero stays 0.000M.
const fmtM3 = (v) => {
  const m = v / 1e6;
  const abs = Math.abs(m);
  // abs < 0.0005 is exactly where toFixed(3) rounds to 0.000.
  const dec = (abs > 0 && abs < 0.0005) ? Math.min(12, 2 - Math.floor(Math.log10(abs))) : 3;
  return m.toFixed(dec) + "M";
};
// fmtInt groups a raw counter with thousands separators (the detail tables show
// exact counts, not the M-abbreviated values used in the heatmap cells).
const fmtInt = (v) => Math.round(v).toLocaleString("en-US");
function fmtPct(d) {
  if (!isFinite(d)) return "new";
  const a = Math.abs(d);
  if (a < 0.005) return "0%";   // rounds to 0.00 — show a clean zero
  return (d > 0 ? "+" : "−") + a.toFixed(2) + "%";
}
// fmtShare formats a self-share / percentage-of-total value (no leading sign).
function fmtShare(p) { return p.toFixed(2) + "%"; }
// Δ% of a function's CEst in run i vs the baseline run. A function absent from
// the baseline (base 0) has no defined %: treat any positive current as "new".
function deltaPct(f, i) {
  // cest maps are per-run, so a function absent from a run has no key — treat as 0.
  const b = matrix.R[matrix.BASE].cest[matrix.funcs[f]] || 0;
  const v = matrix.R[i].cest[matrix.funcs[f]] || 0;
  if (b === 0) return v > 0 ? Infinity : 0;
  return (v - b) / b * 100;
}
function cestOf(f, i) { return matrix.R[i].cest[matrix.funcs[f]] || 0; }
// finiteDelta is deltaPct guarded for plotting: a function absent from the
// baseline has no defined %, so it sits on the baseline (0) rather than ∞.
function finiteDelta(f, i) { const d = deltaPct(f, i); return isFinite(d) ? d : 0; }
function totalDelta(i) { return (matrix.totals[i] - matrix.totals[matrix.BASE]) / matrix.totals[matrix.BASE] * 100; }
// self-share: a function's CEst as a percentage of its run's total CEst.
function selfShare(f, i) { const t = matrix.totals[i]; return t ? cestOf(f, i) / t * 100 : 0; }
function dColor(d) { return Math.abs(d) < 1 ? "#566173" : (d > 0 ? "#b42318" : "#1f7a55"); }
// shortLabel picks the run# segment for compact axis ticks ("4/accept/short_ci" -> "4").
function shortLabel(label) { return String(label).split("/")[0]; }
// labelLines stacks a path label one segment per line ("1/accept/short_ci" ->
// "1/" <br> "accept/" <br> "short_ci") so heatmap columns stay narrow.
function labelLines(label) {
  const parts = String(label).split("/");
  return parts.map((p, i) => esc(p) + (i < parts.length - 1 ? "/" : "")).join("<br>");
}
// diverging heat colour (multi-run change view): green (improvement) ← neutral →
// red (regression). Cells are highlighted only past the per-direction thresholds
// (regressMin / improveMin, set in the legend) so only changes the user cares
// about draw the eye; a function absent from the baseline is "new" (pale pink).
function heatColor(d) {
  if (!isFinite(d)) return "#fbeceb";
  if (d > 0 ? d < regressMin : -d < improveMin) return "transparent"; // d===0 -> blank too
  const mag = Math.min(Math.abs(d), 90) / 90;
  const L = 94 - mag * 42;
  return d > 0 ? "hsl(8 72% " + L + "%)" : "hsl(150 42% " + L + "%)";
}
// hexToRgb parses "#rrggbb" -> [r,g,b]; null on a malformed value.
function hexToRgb(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(String(hex).trim());
  if (!m) return null;
  const n = parseInt(m[1], 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}
// Single-run cost ramp, keyed by t in [0,1] (cheapest → worst): bestColor →
// green → orange → hotColor. BOTH ends are user-configurable from the legend;
// the green/orange midtones are fixed so the path stays a heat ramp (dark-red →
// lighter-red → orange → green → "best"). Returns [r,g,b].
const HEAT_MID = [[0.34, [31, 122, 85]], [0.67, [232, 131, 58]]]; // green, orange
function heatRampRGB(t) {
  t = Math.max(0, Math.min(1, t));
  const best = hexToRgb(bestColor) || [255, 255, 255];
  const worst = hexToRgb(hotColor) || [180, 35, 24];
  const stops = [[0, best], HEAT_MID[0], HEAT_MID[1], [1, worst]];
  for (let i = 1; i < stops.length; i++) {
    if (t <= stops[i][0]) {
      const [p0, c0] = stops[i - 1], [p1, c1] = stops[i];
      const u = p1 === p0 ? 0 : (t - p0) / (p1 - p0);
      return [0, 1, 2].map((k) => Math.round(c0[k] + (c1[k] - c0[k]) * u));
    }
  }
  return worst;
}
function rgbCss(c) { return "rgb(" + c[0] + " " + c[1] + " " + c[2] + ")"; }
// Text colour by background luminance, so it stays legible whatever ramp colours
// the user picks (Rec. 601 luma; < ~150 is dark enough for white text).
function textForBg(c) { return (0.299 * c[0] + 0.587 * c[1] + 0.114 * c[2]) < 150 ? "#fff" : "#0f172a"; }
function heatText(d) { return isFinite(d) && Math.abs(d) >= 48 ? "#fff" : "#0f172a"; }

// column order: load order, by total CEst ascending, or by date (oldest first).
function colOrder() {
  const idx = matrix.R.map((_, i) => i);
  if (orderMode === "cest") {
    return idx.sort((a, b) => matrix.totals[a] - matrix.totals[b]);
  }
  if (orderMode === "date") {
    // Oldest → newest left to right, so columns read as a timeline. Runs with no
    // date (0) sort to the front; load order breaks ties.
    return idx.sort((a, b) => (matrix.R[a].date - matrix.R[b].date) || (a - b));
  }
  return idx;
}
// defaultBaseRun is the baseline used until the user pins one: the oldest run
// (smallest positive date) when ordering by date, else the first loaded run.
// Falls back to run 0 when no run carries a date.
function defaultBaseRun(R) {
  R = R || (full && full.R) || [];
  if (!R.length) return 0;
  if (orderMode !== "date") return 0;
  let best = -1;
  for (let i = 0; i < R.length; i++) {
    if (R[i].date && (best < 0 || R[i].date < R[best].date)) best = i;
  }
  return best >= 0 ? best : 0;
}
// fmtShortDate: compact MM-DD HH:MM for the heatmap date row (full date in title).
function fmtShortDate(epoch) {
  const d = new Date((Number(epoch) || 0) * 1000);
  if (!epoch || isNaN(d.getTime())) return "—";
  const p = (n) => String(n).padStart(2, "0");
  return p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
}

// ---- render --------------------------------------------------------------
// renderAppliedFold keeps the fold paths baked into the current matrix listed
// under the chips (small font), so it stays clear which folds the numbers reflect.
function renderAppliedFold() {
  if (!appliedFoldEl) return;
  const paths = runs.length ? appliedFoldPaths : [];
  if (!paths.length) { appliedFoldEl.hidden = true; appliedFoldEl.innerHTML = ""; return; }
  appliedFoldEl.innerHTML = '<span class="af-lbl">folded</span>'
    + paths.map((p) => '<span class="af-path">' + esc(p) + "</span>").join("")
    + '<button type="button" class="btn btn-sm af-reset" title="Clear all folds and re-parse the runs unfolded">reset fold list</button>';
  appliedFoldEl.hidden = false;
}

function render() {
  syncURL();   // keep the address-bar URL in step with the current view (repo runs)
  renderChips();
  renderAppliedFold();
  updateCompareBar();
  const n = runs.length;
  nrunCount.textContent = String(n);
  const infoCount = $("nrun-info-count");
  if (infoCount) infoCount.textContent = String(n);
  emptyHint.hidden = n > 0;
  const chipsHint = $("chips-hint");
  if (chipsHint) chipsHint.hidden = n === 0;   // only meaningful once chips exist
  clearBtn.hidden = n === 0;
  // Fold only applies once runs are loaded (it re-parses them), matching the old
  // placement inside the controls toolbar that hid when empty.
  if (foldCtl) foldCtl.hidden = n === 0;

  // Keep the view toggle visible even when empty so the layout reads as "results
  // go here"; the data-only controls hide via the controls-empty class.
  controlsEl.hidden = false;
  controlsEl.classList.toggle("controls-empty", n === 0);

  const modeEl = $("nrun-mode");
  if (!matrix || n === 0) {
    if (modeEl) modeEl.textContent = "runs loaded";
    nrunBase.textContent = "—";
    // This path skips updateControls(), so hide the run-dependent "view" selector
    // here too — otherwise it lingers (stale options) after Clear.
    if (focusRunLbl) focusRunLbl.style.display = "none";
    nviewEl.innerHTML = renderEmpty();
    nlegendEl.replaceChildren();
    return;
  }
  // Single run: a cost view (no baseline). One run focused via "view": that run's
  // cost view. Otherwise multi-run: Δ% vs the chosen baseline.
  if (n === 1) {
    if (modeEl) modeEl.textContent = "run · cost view (CEst, hottest on top)";
    nrunBase.textContent = matrix.R[0].label;
  } else if (costRun !== null && costRun < matrix.R.length) {
    if (modeEl) modeEl.textContent = "runs · viewing one run · cost view";
    nrunBase.textContent = matrix.R[costRun].label;
  } else {
    if (modeEl) modeEl.textContent = "runs · baseline =";
    nrunBase.textContent = matrix.R[matrix.BASE].label;
  }
  updateControls();
  syncMenu();
  // A clicked run chip leaves the comparison views for the per-run detail table.
  if (detailRun !== null && detailData) {
    nviewEl.innerHTML = renderDetail();
    nlegendEl.innerHTML = detailLegend();
    placeLegend(false);
    return;
  }
  if (compareRuns) {
    nviewEl.innerHTML = renderCompareDetail();
    nlegendEl.innerHTML = compareLegend();
    placeLegend(false);
    return;
  }
  const avail = nviewEl.clientWidth > 60 ? nviewEl.clientWidth : 1040;
  if (view === "trend") { nviewEl.innerHTML = renderTrend(avail); placeLegend(false); }
  else if (view === "diverge") { nviewEl.innerHTML = renderDiverge(); placeLegend(false); }
  else { nviewEl.innerHTML = renderHeat(); placeLegend(true); }
  nlegendEl.innerHTML = legendFor();
}

// placeLegend moves the shared legend above or below the view container. The
// heatmap reads top-down (hottest functions first), so its legend belongs above
// the table; every other view keeps the legend below.
function placeLegend(above) {
  const parent = nviewEl.parentNode;
  nlegendEl.classList.toggle("above", above);
  if (above) {
    if (nviewEl.previousSibling !== nlegendEl) parent.insertBefore(nlegendEl, nviewEl);
  } else if (nviewEl.nextSibling !== nlegendEl) {
    parent.insertBefore(nlegendEl, nviewEl.nextSibling);
  }
}

// updateControls hides the controls a view doesn't use: divergence has its own
// in-view current/reference/top-N selectors, so the Δ-mode toggle, ordering,
// and threshold pill don't apply there.
function updateControls() {
  // The detail view drives its own sorting/filtering, so the Δ-mode toggle,
  // threshold pill, and functions-count cap don't apply (the table is full and
  // already filtered by PATTERNS). The patterns field stays — it filters detail.
  const detail = detailRun !== null;
  const compare = compareRuns !== null;
  // The value-mode toggle (Δ% vs baseline, etc.) is meaningless in a cost view —
  // a single run, or one run focused via "view" — so hide it there too.
  const costView = runs.length === 1 || costRun !== null;
  const hide = detail || compare || view === "diverge" || costView;
  valseg.style.display = hide ? "none" : "";
  const fnLbl = topnInput.closest(".field-lbl");
  // The shared functions top-N is hidden in single-run detail (full table) and in
  // compare (which has its own functions selector in its header).
  if (fnLbl) fnLbl.style.display = (detail || compare) ? "none" : "";
  // "view" selector (focus one run's cost heatmap): only in the heatmap with ≥2
  // runs loaded. Populated from the runs each time so labels/indices stay current.
  const showFocus = view === "heat" && !detail && !compare && runs.length >= 2;
  // Toggle via style.display, not the hidden attribute: .field-lbl.inline sets
  // display:inline-flex, which overrides [hidden] and would keep it visible.
  if (focusRunLbl) focusRunLbl.style.display = showFocus ? "" : "none";
  if (showFocus) populateFocusRun();
  // No comparison view is "current" while a detail or compare view is open.
  viewseg.querySelectorAll("button").forEach((b) =>
    b.classList.toggle("on", !detail && !compare && b.dataset.view === view));
}
// populateFocusRun fills the "view" selector: all-runs change view (default) plus
// one option per run (its single-run cost heatmap), reflecting the current focus.
function populateFocusRun() {
  if (!focusRunSel || !matrix) return;
  let html = '<option value="all">all runs (Δ vs baseline)</option>';
  matrix.R.forEach((r, i) => {
    html += '<option value="' + i + '">' + esc(r.label) + " (cost)</option>";
  });
  focusRunSel.innerHTML = html;
  focusRunSel.value = costRun === null ? "all" : String(costRun);
}

function renderChips() {
  chipsEl.replaceChildren();
  // Display chips oldest → newest by run date (load order breaks ties), matching
  // the heatmap's default date column order. `i` stays the run's load-order index
  // used everywhere else (baseline, compare selection, totals[i], matrix.R[i]).
  const order = runs.map((_, i) => i).sort((a, b) => (runs[a].date - runs[b].date) || (a - b));
  order.forEach((i) => {
    const r = runs[i];
    const isBase = matrix && i === matrix.BASE;
    const total = matrix ? matrix.totals[i] : 0;
    const pct = matrix ? Math.round(total / matrix.maxTotal * 100) : 0;

    const chip = document.createElement("div");
    chip.className = "rchip" + (isBase ? " base" : "") + (i === detailRun ? " open" : "")
      + (compareSel.includes(i) ? " sel" : "");
    // Plain click opens this run's detail; Ctrl/⌘-click toggles it in the compare
    // selection (the corner checkbox does the same). Keyboard-accessible too.
    chip.tabIndex = 0;
    chip.setAttribute("role", "button");
    chip.title = "Click: this run's detail · Ctrl/⌘-click or tick: select for compare";
    chip.addEventListener("click", (e) => {
      if (e.metaKey || e.ctrlKey) toggleCompare(i);
      else openDetail(i);
    });
    chip.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDetail(i); }
    });

    // Corner checkbox: tick to select this run for the multi-run compare.
    const cbx = document.createElement("input");
    cbx.type = "checkbox";
    cbx.className = "rcmp";
    cbx.checked = compareSel.includes(i);
    cbx.title = "Select for multi-run compare (max " + COMPARE_MAX + ")";
    cbx.addEventListener("click", (e) => e.stopPropagation());
    cbx.addEventListener("change", () => toggleCompare(i));

    const lbl = document.createElement("div");
    lbl.className = "rlabel";
    lbl.textContent = r.label;

    const bar = document.createElement("div");
    bar.className = "cb";
    const fill = document.createElement("i");
    fill.style.width = pct + "%";
    bar.appendChild(fill);

    const rn = document.createElement("div");
    rn.className = "rn";
    rn.textContent = matrix ? fmtM(total) : "—";

    const rm = document.createElement("button");
    rm.className = "rm";
    rm.textContent = "×";
    rm.title = "Remove this run";
    // Stop the chip's click from also firing (which would open the detail view).
    rm.addEventListener("click", (e) => { e.stopPropagation(); removeRun(i); });

    chip.append(cbx, lbl, bar, rn);
    // Baseline picker (multi-run only): which run Δ% is measured against. With a
    // single run the heatmap is a cost view, so there is no baseline to pick.
    if (matrix && runs.length >= 2) {
      const baseBtn = document.createElement("button");
      baseBtn.className = "rbase" + (isBase ? " on" : "");
      baseBtn.textContent = isBase ? "baseline" : "set base";
      baseBtn.title = isBase
        ? "This run is the baseline — Δ% is measured against it"
        : "Make this run the baseline (Δ% reference)";
      baseBtn.addEventListener("click", (e) => { e.stopPropagation(); setBaseRun(i); });
      chip.append(baseBtn);
    }
    chip.append(rm);
    chipsEl.appendChild(chip);
  });
}

// setBaseRun makes run i the baseline (Δ% reference). Display-only: the parse is
// unchanged, so just repoint BASE and re-render.
function setBaseRun(i) {
  if (!full) return;
  baseRunPinned = true; // an explicit pick overrides the date/load default
  if (i === baseRun) return;
  baseRun = i;
  full.BASE = i;
  if (matrix) matrix.BASE = i;
  render();
}

// heatCellLabel is the text shown in a non-baseline heatmap cell, per value mode.
function heatCellLabel(f, i) {
  switch (valMode) {
    case "abs": return fmtM(cestOf(f, i));            // CEst cycles
    case "pct": return fmtShare(selfShare(f, i));     // CEst % of run total
    default: return fmtPct(deltaPct(f, i));           // Δ% vs baseline
  }
}

function renderHeat() {
  // One run loaded, or one run focused via the "view" selector: a cost view
  // (where the cycles go) of that run, not the multi-run change view.
  if (matrix.R.length === 1) return renderHeatCost(0);
  if (costRun !== null && costRun < matrix.R.length) return renderHeatCost(costRun);
  const { funcs, R, BASE } = matrix;
  const cols = colOrder();
  // The baseline column's green frame is drawn with box-shadow; suppress the
  // grey border on its own right edge and on the cell just to its left so the
  // frame is the only thing at both edges (otherwise one side shows grey+green).
  const basePos = cols.indexOf(BASE);
  const preBaseRun = basePos > 0 ? cols[basePos - 1] : null; // run index left of base
  const fnPreBase = basePos === 0 ? " base-left" : "";       // base is first col -> the fn column is to its left

  let h = '<table class="heat"><thead><tr><th class="fn' + fnPreBase + '">function</th>';
  cols.forEach((i) => {
    let cls = i === BASE ? "base-col" : "";
    if (i === preBaseRun) cls += (cls ? " " : "") + "base-left";
    // Clicking a run's column header opens that run's detail view (same as
    // clicking its chip). data-runcol carries the run index for the delegate.
    cls += (cls ? " " : "") + "hcol";
    // The baseline is marked with a "base" label above its column header.
    const tag = i === BASE ? '<div class="base-tag">base</div>' : "";
    h += '<th class="' + cls + '" data-runcol="' + i + '" title="Open the detailed per-function view for '
      + esc(R[i].label) + '">' + tag + labelLines(R[i].label) + "</th>";
  });
  h += "</tr></thead><tbody>";
  // Date row, just below the header: each run's date under its column (full date
  // in the tooltip). Sort columns by date from the ⋯ menu (Column order → date).
  h += '<tr class="daterow"><td class="fn' + fnPreBase + '">date</td>';
  cols.forEach((i) => {
    let cls = "datecell";
    if (i === BASE) cls += " base-col";
    if (i === preBaseRun) cls += " base-left";
    h += '<td class="' + cls + '" title="' + esc(fmtStoreDate(R[i].date)) + '">' + esc(fmtShortDate(R[i].date)) + "</td>";
  });
  h += "</tr>";
  funcs.forEach((fn, f) => {
    h += '<tr><td class="fn' + fnPreBase + '"><span class="fnname copyfn" data-fn="' + esc(fn) + '" title="' + esc(fn) + '">' + esc(fn) + "</span></td>";
    cols.forEach((i) => {
      if (i === BASE) {
        // Baseline column shows the reference CEst (M) for each function; the
        // "base" marker sits above the column header, not in every cell.
        h += '<td class="cell base-col" style="background:#e7f3ec;color:#1f7a55;">' + fmtM(cestOf(f, BASE)) + "</td>";
        return;
      }
      const d = deltaPct(f, i);              // colour always tracks Δ% vs the baseline run
      const cls = "cell" + (i === preBaseRun ? " base-left" : "");
      h += '<td class="' + cls + '" style="background:' + heatColor(d) + ";color:" + heatText(d)
        + '">' + heatCellLabel(f, i) + "</td>";
    });
    h += "</tr>";
  });
  h += "</tbody></table>";
  return h;
}

// renderHeatCost is the single-run heatmap: a cost ranking (most expensive
// function on top) coloured on the configurable ramp, so you see where the cycles
// go within one run. No baseline, no Δ.
//
// The colour scale is LOG-spread over the displayed functions' CEst range, not a
// linear share of the max: CPU cost is heavily skewed (one function can be 20% of
// the run while the rest are <3% each), so a linear scale leaves everything but
// the top near the cold end and the orange/green midtones never appear. Log
// spreads the ranked list across the whole ramp while keeping magnitude order.
function renderHeatCost(idx) {
  const { funcs, R } = matrix;
  const run = R[idx];
  const total = matrix.totals[idx] || 1;
  const vals = funcs.map((fn) => run.cest[fn] || 0);
  const maxC = vals.reduce((m, v) => (v > m ? v : m), 0);
  const pos = vals.filter((v) => v > 0);
  const minC = pos.length ? Math.min.apply(null, pos) : 1;
  const lnMin = Math.log(minC), span = Math.log(maxC || 1) - lnMin;

  // Column sort: by name, or by cost (CEst and % of run share one order, since
  // % is just CEst ÷ the run total). Colour t is per-function, so re-ordering
  // rows never changes a cell's colour.
  const byName = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  const order = funcs.slice().sort((a, b) => {
    if (costSort.key === "name") return costSort.dir === "asc" ? byName(a, b) : byName(b, a);
    const d = (run.cest[a] || 0) - (run.cest[b] || 0); // ascending by cost
    return (costSort.dir === "asc" ? d : -d) || byName(a, b);
  });
  const sortTh = (key, label, cls) => {
    const on = costSort.key === key;
    const arr = on ? (costSort.dir === "asc" ? "▲" : "▼") : "";
    return '<th class="' + cls + " costsort" + (on ? " on" : "") + '" data-costsort="' + key
      + '" title="Click to sort; click again to flip">' + label + '<span class="darr">' + arr + "</span></th>";
  };

  let h = '<table class="heat heat-cost"><thead><tr>'
    + sortTh("name", "function", "fn")
    + sortTh("cest", "CEst", "hcol-cost")
    + sortTh("pct", "% of run", "hcol-cost")
    + "</tr></thead><tbody>";
  order.forEach((fn) => {
    const c = run.cest[fn] || 0;
    const t = c <= 0 ? 0 : (span > 0 ? (Math.log(c) - lnMin) / span : 1);
    const rgb = heatRampRGB(t);
    const cell = ' style="background:' + rgbCss(rgb) + ";color:" + textForBg(rgb) + '"';
    h += '<tr><td class="fn"><span class="fnname copyfn" data-fn="' + esc(fn) + '" title="' + esc(fn) + '">' + esc(fn) + "</span></td>"
      + '<td class="cell cost"' + cell + ">" + fmtM(c) + "</td>"
      + '<td class="cell cost"' + cell + ">" + fmtShare(c / total * 100) + "</td>"
      + "</tr>";
  });
  h += "</tbody></table>";
  return h;
}

// ---- detail view ---------------------------------------------------------
// One run's full per-function breakdown: every function with its 9 raw
// Callgrind counters + CEst, filtered by the PATTERNS field and sortable on any
// column. A second table sums the counters of every function matching each
// PATTERNS term (one row per term). Entered by clicking a run chip; left via the
// "Back" button or any comparison-view button. detailData is parsed once per run
// (cestRunDetail), so sorting and filtering here never re-parse.

// openDetail parses the clicked run (if not already cached) and switches to its
// detail view. Sorts reset to the default (CEst, descending) for a fresh run.
function openDetail(i) {
  if (!wasmReady) { showError("WASM still loading — try again in a moment."); return; }
  if (!runs[i]) return;
  // Cache the per-run detail parse (all 9 counters per function) on the run,
  // keyed by fold state, exactly like the cestRunCEst cache. Re-opening a run's
  // detail (or returning to it) is then instant; only a first open or a fold
  // change actually re-parses in WASM.
  const fp = foldPaths();
  const foldKey = fp.join("\n");
  let cached = runs[i]._detailCache;
  if (!cached || cached.foldKey !== foldKey) {
    const r = cestRunDetail(runs[i].files, fp);
    if (r.error) { showError(r.error); return; }
    cached = { foldKey, data: r };
    runs[i]._detailCache = cached;
  }
  hideError();
  detailData = cached.data;
  detailRun = i;
  detailFnSort = { key: "CEst", dir: "desc" };
  detailPatSort = { key: "CEst", dir: "desc" };
  render();
}

// closeDetail returns to the comparison views (keeps the loaded runs).
function closeDetail() {
  detailRun = null;
  detailData = null;
  render();
}

// ---- compare view (2–3 runs) ---------------------------------------------
// A side-by-side per-function CEst table for the runs marked via the chip
// checkboxes / Ctrl-click or the heatmap headers. Diffs are measured against
// each function's lowest-CEst (cheapest) run, so every row shows how much
// costlier the others are; a "spread" column gives worst ÷ best − 1. CEst only
// for now (the most important stat); the raw counters can follow.

// toggleCompare adds/removes run i from the compare selection (max COMPARE_MAX).
// If the compare view is open it tracks the selection live (≥2 runs keeps it
// open, <2 closes it). render() reverts a stray checkbox when already at the max.
function toggleCompare(i) {
  const at = compareSel.indexOf(i);
  if (at >= 0) compareSel.splice(at, 1);
  else if (compareSel.length < COMPARE_MAX) compareSel.push(i);
  if (compareRuns) compareRuns = compareSel.length >= 2 ? compareSel.slice() : null;
  render();
}

// updateCompareBar paints the action bar above the views: how many runs are
// staged, plus Compare / Back / Clear.
function updateCompareBar() {
  const bar = $("cmp-bar");
  if (!bar) return;
  const n = compareSel.length;
  if (n === 0) { bar.hidden = true; bar.innerHTML = ""; return; }
  bar.hidden = false;
  // Two left-aligned buttons: Compare Selected (needs ≥2) and Clear. The compare
  // view's own header carries the "← Back to comparison" button.
  bar.innerHTML =
    '<button class="btn btn-sm btn-primary" data-cmp-go' + (n < 2 ? " disabled" : "") + ">Compare Selected</button>"
    + '<button class="btn btn-sm" data-cmp-clear>Clear</button>';
}

// cmpHeat: red tint scaling with how much costlier (%) than the row's best run.
function cmpHeat(d) {
  if (!isFinite(d)) return "#fbeceb";
  if (d < 1) return "transparent";
  const mag = Math.min(d, 90) / 90;
  return "hsl(8 72% " + (94 - mag * 42) + "%)";
}

// cmpTh renders a sortable compare-table header. key is 'name', 'spread', or a
// run index (as a string) for that run's CEst column.
function cmpTh(key, label, sub) {
  const active = String(compareSort.key) === key;
  const arrow = active ? (compareSort.dir === "asc" ? "▲" : "▼") : "";
  const cls = "dsort" + (active ? " on" : "") + (key === "name" ? " col-name" : " col-num");
  // `sub` is an optional second line under the label (the run date for run columns).
  return '<th class="' + cls + '" data-cmpsort="' + key + '">' + label
    + '<span class="darr">' + arrow + "</span>"
    // The trailing empty .darr matches the arrow's reserved width on the label
    // line, so the date right-aligns to the same edge as the label.
    + (sub ? '<span class="cmp-date">' + sub + '<span class="darr"></span></span>' : "") + "</th>";
}

function compareLegend() {
  return "<span>CEst per run · each function's diffs are vs its <b>lowest-CEst</b> (best) run "
    + '(<span style="color:#1f7a55;font-weight:700;">green</span> = best, redder = costlier) · '
    + "<b>spread</b> = worst ÷ best − 1 · sorted by spread · the <b>functions</b> selector "
    + "sets how many to show (default All) · the <b>patterns</b> field filters.</span>";
}

// ensureCompareData (re)computes the Go-side compare rows for the current
// selection via the cestCompare bridge, caching by the selected run set so a
// sort / patterns / cap change re-renders without recomputing. The lowest-CEst
// baseline, Δ% vs best, and spread are all computed in Go (internal/cest), shared
// with the CLI's --compare — no compare math in JS.
function ensureCompareData() {
  const key = compareRuns ? compareRuns.join(",") : "";
  if (key === compareDataKey && compareData) return;
  compareDataKey = key;
  if (!compareRuns) { compareData = null; return; }
  if (typeof cestCompare !== "function") {
    showError("Compare bridge unavailable — rebuild cest-analyzer.wasm.");
    compareData = null; return;
  }
  const payload = compareRuns.map((i) => ({ label: full.R[i].label, total: full.R[i].total, cest: full.R[i].cest }));
  const res = cestCompare(payload);
  if (res.error) { showError(res.error); compareData = null; return; }
  compareData = res.functions; // [{ name, cest:[], deltaPct:[], best, spreadPct }] sorted spread-desc
}

// renderCompareDetail builds the 2–3 run CEst table from the Go-computed compare
// rows (see ensureCompareData). JS only filters (patterns), sorts (the column the
// user picked), caps (the functions selector), and renders — the math is Go's.
function renderCompareDetail() {
  const sel = compareRuns, R = full.R;
  ensureCompareData();
  if (!compareData) {
    return '<div class="detail-head"><button class="btn btn-sm" data-cmp-back>← Back to heatmap</button>'
      + '<span class="detail-title">Compare unavailable</span></div>';
  }

  const pats = patternsInput.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  let rows = pats.length
    ? compareData.filter((r) => { const l = r.name.toLowerCase(); return pats.some((p) => l.includes(p)); })
    : compareData.slice();

  const dir = compareSort.dir === "asc" ? 1 : -1;
  rows.sort((a, b) => {
    if (compareSort.key === "name") return (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) * dir;
    if (compareSort.key === "spread") {
      // 'new' (infinite spread) always sinks to the bottom, in BOTH directions.
      const ai = !isFinite(a.spreadPct), bi = !isFinite(b.spreadPct);
      if (ai || bi) return ai && bi ? 0 : (ai ? 1 : -1);
      return (a.spreadPct - b.spreadPct) * dir;
    }
    const k = sel.indexOf(compareSort.key);  // a run-index column
    return (a.cest[k] - b.cest[k]) * dir;
  });

  const shown = compareTopN === "all" ? rows : rows.slice(0, Math.max(1, compareTopN));
  const span = sel.length + 2;

  // Compare has its own functions cap (default All), independent of the heatmap's
  // top-N, so showing all rows here doesn't blow up the heatmap.
  const topnSel = '<select data-cmp-topn class="dvg-sel">'
    + '<option value="all"' + (compareTopN === "all" ? " selected" : "") + ">All (" + rows.length + ")</option>"
    + [10, 25, 50, 100, 250].map((nn) =>
        '<option value="' + nn + '"' + (compareTopN === nn ? " selected" : "") + ">top " + nn + "</option>").join("")
    + "</select>";

  let h = '<div class="detail-head">'
    + '<button class="btn btn-sm" data-cmp-back>← Back to heatmap</button>'
    + '<label class="field-lbl inline">functions ' + topnSel + "</label>"
    + '<span class="detail-title">Compare · <b>' + sel.map((ri) => esc(R[ri].label)).join("</b> · <b>") + "</b>"
    + ' · <span class="detail-count">' + shown.length + " of " + rows.length
    + (rows.length === 1 ? " function" : " functions") + "</span></span></div>";

  h += '<div class="detail-scroll"><table class="detail cmp"><thead><tr>';
  h += cmpTh("name", "Function");
  sel.forEach((ri) => { h += cmpTh(String(ri), esc(R[ri].label),
    '<span title="' + esc(fmtStoreDate(R[ri].date)) + '">' + esc(fmtShortDate(R[ri].date)) + "</span>"); });
  h += cmpTh("spread", "spread");
  h += "</tr></thead><tbody>";
  if (shown.length === 0) {
    h += '<tr><td class="detail-empty" colspan="' + span + '">No functions match the PATTERNS filter.</td></tr>';
  } else {
    shown.forEach((row) => {
      h += '<tr><td class="col-name"><span class="dname" title="' + esc(row.name) + '">' + esc(row.name) + "</span></td>";
      row.cest.forEach((c, k) => {
        const isMin = k === row.best;
        const dpct = row.deltaPct[k];
        const tag = isMin
          ? '<span class="cmp-best">best</span>'
          : '<span class="cmp-d">+' + (isFinite(dpct) ? (dpct < 0.05 ? "0%" : dpct.toFixed(1) + "%") : "∞") + "</span>";
        h += '<td class="col-num" style="background:' + (isMin ? "#e7f3ec" : cmpHeat(dpct)) + '">'
          + fmtM3(c) + " " + tag + "</td>";
      });
      h += '<td class="col-num cmp-spread">'
        + (isFinite(row.spreadPct) ? (row.spreadPct < 0.05 ? "0%" : "+" + row.spreadPct.toFixed(1) + "%") : "new") + "</td>";
      h += "</tr>";
    });
  }
  h += "</tbody></table></div>";
  return h;
}

// patternTerms returns the de-duplicated, lower-cased PATTERNS terms (the
// detail tables share the existing patterns field with the comparison views).
function patternTerms() {
  const seen = new Set();
  return patternsInput.value.trim().toLowerCase().split(/\s+/).filter((t) => {
    if (!t || seen.has(t)) return false;
    seen.add(t);
    return true;
  });
}

// detailFilterFns keeps the run's functions whose name contains any PATTERNS
// term (case-insensitive); empty patterns => every function.
function detailFilterFns() {
  const pats = patternTerms();
  if (!pats.length) return detailData.functions.slice();
  return detailData.functions.filter((f) => {
    const l = f.name.toLowerCase();
    return pats.some((p) => l.includes(p));
  });
}

// detailPatternRows builds one aggregated row per PATTERNS term: the field-wise
// sum of every function matching that term. CEst is linear in the counters, so
// summing per-function CEst matches summing the counters then computing CEst.
function detailPatternRows() {
  return patternTerms().map((term) => {
    const row = { name: term };
    COUNTER_COLS.forEach((c) => { row[c] = 0; });
    detailData.functions.forEach((f) => {
      if (f.name.toLowerCase().includes(term)) {
        COUNTER_COLS.forEach((c) => { row[c] += f[c]; });
      }
    });
    return row;
  });
}

// sortRows orders rows by the chosen column: the name column sorts
// lexicographically, every counter column numerically. dir 'asc' | 'desc'.
function sortRows(rows, sort) {
  const k = sort.key, dir = sort.dir === "asc" ? 1 : -1;
  return rows.slice().sort((a, b) => {
    if (k === "name") return dir * String(a.name).localeCompare(String(b.name));
    return dir * (a[k] - b[k]);
  });
}

// sortableTh renders a clickable header cell with the active-sort arrow.
function sortableTh(table, col, label, sort) {
  const active = sort.key === col;
  const arrow = active ? (sort.dir === "asc" ? "▲" : "▼") : "";
  const cls = "dsort" + (active ? " on" : "") + (col === "name" ? " col-name" : " col-num");
  const desc = COUNTER_DESC[col] ? " - " + COUNTER_DESC[col] : "";
  return '<th class="' + cls + '" data-sorttable="' + table + '" data-sortcol="' + col
    + '" title="Sort by ' + esc(label) + desc + '">' + esc(label)
    + '<span class="darr">' + arrow + "</span></th>";
}

// detailHeader builds a full <tr> of sortable headers for one of the two tables.
function detailHeader(table, firstLabel, sort) {
  let h = "<tr>" + sortableTh(table, "name", firstLabel, sort);
  COUNTER_COLS.forEach((c) => { h += sortableTh(table, c, c, sort); });
  return h + "</tr>";
}

// detailRowHtml renders one data row (name cell + the 10 numeric cells).
// isFn marks a real function row (vs a pattern-aggregate row): only function
// rows get the copy-fold-path affordance, since a pattern row is a sum of many
// functions, not a single call node.
function detailRowHtml(r, isFn) {
  const nameCls = isFn ? "dname copyfn" : "dname";
  const fnAttr = isFn ? ' data-fn="' + esc(r.name) + '"' : "";
  let h = '<tr><td class="col-name"><span class="' + nameCls + '"' + fnAttr + ' title="' + esc(r.name) + '">' + esc(r.name) + "</span></td>";
  COUNTER_COLS.forEach((c) => { h += '<td class="col-num">' + fmtInt(r[c]) + "</td>"; });
  return h + "</tr>";
}

function renderDetail() {
  const label = runs[detailRun] ? runs[detailRun].label : "";
  const fns = sortRows(detailFilterFns(), detailFnSort);
  const patRows = sortRows(detailPatternRows(), detailPatSort);
  const span = COUNTER_COLS.length + 1;
  const hasPat = patternTerms().length > 0;

  let h = '<div class="detail-head">'
    + '<button class="btn btn-sm" data-detail-back>← Back to heatmap</button>'
    + '<span class="detail-title">Detailed view · <b>' + esc(label) + "</b>"
    + ' · total CEst <b class="mono">' + fmtInt(detailData.total.CEst) + "</b>"
    + ' · <span class="detail-count">' + fns.length + (fns.length === 1 ? " function" : " functions")
    + (hasPat ? " matching filter" : "") + "</span></span></div>";

  h += '<div class="detail-scroll"><table class="detail"><thead>'
    + detailHeader("fn", "Function Name", detailFnSort) + "</thead><tbody>";
  if (fns.length === 0) {
    h += '<tr><td class="detail-empty" colspan="' + span + '">No functions match the PATTERNS filter.</td></tr>';
  } else {
    fns.forEach((f) => { h += detailRowHtml(f, true); });
  }
  h += "</tbody></table></div>";

  h += '<div class="detail-subhead">Pattern aggregation'
    + '<span class="detail-sub-note">summed counters of every function whose name matches each PATTERNS term</span></div>';
  h += '<div class="detail-scroll"><table class="detail pat"><thead>'
    + detailHeader("pat", "Pattern Name", detailPatSort) + "</thead><tbody>";
  if (patRows.length === 0) {
    h += '<tr><td class="detail-empty" colspan="' + span
      + '">Type space-separated terms in the <b>PATTERNS</b> field above to aggregate matching functions.</td></tr>';
  } else {
    patRows.forEach((p) => { h += detailRowHtml(p, false); });
  }
  h += "</tbody></table></div>";
  return h;
}

function detailLegend() {
  return "<span>All values are <b>self</b> counts for this run · <b>CEst</b> is the cycle estimate, "
    + "the other 9 columns are the raw Callgrind counters it is built from · "
    + "click any column header to sort · the function list follows the <b>PATTERNS</b> filter.</span>";
}

// renderEmpty paints a placeholder shaped like the currently selected view, so
// it reads as "this view's results go here" before any runs are added.
function renderEmpty() {
  if (view === "trend") return emptyTrend();
  if (view === "diverge") return emptyDiverge();
  return emptyHeat();
}
// Heatmap empty state: the "function" first column as a skeleton + a hint.
function emptyHeat() {
  const widths = [70, 88, 54, 76, 62, 48];
  let rows = "";
  widths.forEach((w) => { rows += '<div class="sk-row"><span class="sk-bar" style="width:' + w + '%"></span></div>'; });
  return '<div class="empty-view">'
    + '<div class="sk-col"><div class="sk-head">function</div>' + rows + "</div>"
    + '<div class="empty-msg"><div class="empty-card"><b>Heatmap appears here</b>'
    + "<span>Add one run to see where its cycles go, or two or more to compare them against a chosen baseline run.</span></div></div>"
    + "</div>";
}
// Trends empty state: the plot-functions picker (ghost chips), a chart frame
// with the baseline run line, and the legend — mirroring the real view.
function emptyTrend() {
  const widths = [58, 46, 70, 38, 54, 64, 42, 60];
  const chips = widths.map((w) => '<span class="tfn dis"><span class="dot"></span><span class="sk-pill" style="width:' + w + 'px"></span></span>').join("");
  const pick = '<div class="trend-pick"><span class="lbl">plot functions</span>' + chips + '<span class="cnt">0 / 5 · total always shown</span></div>';
  const chart = '<div class="sk-chart">'
    + '<div class="sk-baseline"></div><span class="sk-baseline-lbl">baseline run (0%)</span>'
    + '<div class="empty-msg"><div class="empty-card"><b>Trends chart appears here</b><span>Add runs to plot Δ% vs the baseline run across runs (load order).</span></div></div>'
    + "</div>";
  const leg = '<div class="trend-leg"><span style="color:#0f172a;font-weight:700;">— total CEst</span><span>Δ% vs baseline · load order</span></div>';
  return pick + chart + leg;
}
// Divergence empty state: the current/vs header (ghost selectors), the centered
// axis, and a hint.
function emptyDiverge() {
  const head = '<div class="dvg-head"><span class="dvg-h-lbl">current</span><span class="sk-pill sk-sel"></span>'
    + '<span class="dvg-h-lbl">vs</span><span class="sk-pill sk-sel"></span>'
    + '<span class="dvg-leg"><span class="sw up"></span>increased<span class="sw down"></span>decreased</span></div>';
  const body = '<div class="sk-chart" style="height:300px;"><div class="sk-vcenter"></div>'
    + '<div class="empty-msg"><div class="empty-card"><b>Divergence bars appear here</b><span>Add runs to compare each function’s self-share (pp) vs the baseline run.</span></div></div>'
    + "</div>";
  return head + body;
}

function legendFor() {
  if (view === "diverge") {
    return '<span>Each bar = a function’s change in <b>self-share</b> of total CEst, current run vs the '
      + 'chosen reference (the <b>baseline run</b> by default, or any run) · '
      + '<span style="color:#b42318;font-weight:700;">red</span> gained share / '
      + '<span style="color:#1f7a55;font-weight:700;">green</span> lost share · sorted by current share. '
      + '<b>pp</b> = percentage points.</span>';
  }
  if (view === "trend") {
    return valMode === "abs"
      ? '<span>Total CEst cycles per run · ● baseline run · load order. Pick up to 5 functions to plot.</span>'
      : '<span>Δ% vs the baseline run (baseline = 0%). Watch where total rises above 0. Pick up to 5 functions to plot.</span>';
  }
  // Single-run (or one run focused via "view"): a cost ramp, both ends configurable.
  if (matrix && (matrix.R.length === 1 || costRun !== null)) {
    const swatch = "linear-gradient(90deg," + esc(bestColor) + ",#1f7a55,#e8833a," + esc(hotColor) + ")";
    return "<span>cells = <b>CEst cycles</b> (self, M = million), most expensive on top · log-spread colour</span>"
      + '<span class="legramp"><span class="legramp-bar" style="background:' + swatch + '"></span></span>'
      + '<span class="legthresh">cheapest '
      + '<input type="color" id="bestcolor" class="legcolor-inp" value="' + esc(bestColor) + '" '
      + 'title="Colour of the cheapest cells (cold end of the ramp)." />'
      + ' → worst '
      + '<input type="color" id="hotcolor" class="legcolor-inp" value="' + esc(hotColor) + '" '
      + 'title="Colour of the most expensive cells (hot end). The ramp blends worst → orange → green → cheapest." /></span>';
  }
  // Multi-run heatmap: Δ% vs the chosen baseline run, diverging colour.
  let cells;
  if (valMode === "abs") cells = "cells = <b>CEst cycles</b> (self, M = million)";
  else if (valMode === "pct") cells = "cells = <b>CEst %</b> — function’s share of its run’s total CEst";
  else cells = "cells = <b>Δ % vs baseline</b>";
  return "<span>" + cells + " · colour = Δ% vs baseline run</span>"
    + '<span class="legthresh"><span class="swatch" style="background:hsl(8 72% 70%)"></span>'
    + 'regression — highlight Δ ≥ '
    + '<input type="number" id="regress-thresh" class="legthresh-inp" value="' + regressMin + '" min="0" max="100" step="1" '
    + 'title="Cells highlight red only when Δ% vs the baseline run (worse) reaches this." /> %</span>'
    + '<span class="legthresh"><span class="swatch" style="background:hsl(150 42% 70%)"></span>'
    + 'improvement — highlight Δ ≤ −'
    + '<input type="number" id="improve-thresh" class="legthresh-inp" value="' + improveMin + '" min="0" max="100" step="1" '
    + 'title="Cells highlight green only when Δ% vs the baseline run (better) reaches this magnitude." /> %</span>'
    + '<span><span class="swatch" style="background:#e7f3ec"></span>baseline run</span>'
    + '<span class="legthresh-note">smaller changes stay blank</span>';
}

// ---- trends view ---------------------------------------------------------
// Line chart over the runs in load order. delta mode: Δ% vs baseline (baseline 0).
// abs mode: total CEst cycles. The "total CEst" line is always drawn; up to 5
// functions are selectable via the picker (default: the two biggest regressors
// in the latest run).
function renderTrend(W) {
  const { funcs, R, totals, BASE } = matrix;
  const N = R.length;
  const hgt = 430, L = 54, Rp = 18, T = 22, B = 36;

  const reg = funcs.map((_, f) => [finiteDelta(f, N - 1), f]).sort((a, b) => b[0] - a[0]);
  if (trendFns === null) {
    trendFns = [];
    for (let k = 0; k < reg.length && trendFns.length < 2; k++) trendFns.push(reg[k][1]);
  }
  const colorOf = {};
  trendFns.forEach((f, idx) => { colorOf[f] = TREND_COLORS[idx % TREND_COLORS.length]; });
  const atMax = trendFns.length >= 5;

  let pick = '<div class="trend-pick"><span class="lbl">plot functions</span>';
  funcs.forEach((fn, f) => {
    const on = trendFns.indexOf(f) >= 0;
    const dis = !on && atMax;
    const dot = on ? colorOf[f] : "var(--line-strong)";
    pick += '<span class="tfn' + (on ? " on" : "") + (dis ? " dis" : "") + '" data-trendfn="' + f + '">'
      + '<span class="dot" style="background:' + dot + '"></span>' + esc(fn) + "</span>";
  });
  pick += '<span class="cnt">' + trendFns.length + ' / 5 plotted</span></div>';

  // per-mode plotting: value accessor, the reference (baseline) line, the
  // y-formatter, and whether a "total CEst" line is meaningful (it isn't for
  // CEst %, where every run's total share is 100%).
  const series = [];
  let valueFn, totalArr, refVal = null, refLabel = "", yfmt, hasTotal = true, modeLabel;
  if (valMode === "abs") {
    valueFn = (f, i) => cestOf(f, i);
    totalArr = totals.slice();
    refVal = totals[BASE]; refLabel = "baseline total (" + fmtM(totals[BASE]) + ")"; yfmt = fmtM;
    modeLabel = "absolute CEst cycles";
  } else if (valMode === "pct") {
    valueFn = (f, i) => selfShare(f, i);
    hasTotal = false; // total self-share is always 100%
    yfmt = (v) => v.toFixed(1) + "%";
    modeLabel = "CEst % of run total";
  } else {
    valueFn = (f, i) => finiteDelta(f, i);
    totalArr = R.map((_, i) => totalDelta(i));
    refVal = 0; refLabel = "baseline run (0%)"; yfmt = (v) => Math.round(v) + "%";
    modeLabel = "Δ% vs baseline";
  }
  trendFns.forEach((f) => series.push({ arr: R.map((_, i) => valueFn(f, i)), col: colorOf[f], sw: 2.2, name: funcs[f] }));
  if (hasTotal) series.push({ arr: totalArr, col: "#0f172a", sw: 3, name: "total CEst" });
  const totLine = hasTotal ? series[series.length - 1].arr : null;
  const allv = series.reduce((a, s) => a.concat(s.arr), refVal === null ? [] : [refVal]);
  let ymin = Math.min.apply(null, allv), ymax = Math.max.apply(null, allv);
  if (!isFinite(ymin) || !isFinite(ymax)) { ymin = 0; ymax = 1; } // no series (e.g. filter matched nothing)
  const padv = (ymax - ymin) * 0.12 || 1; ymin -= padv; ymax += padv;
  const X = (i) => N <= 1 ? (L + (W - L - Rp) / 2) : (L + (i / (N - 1)) * (W - L - Rp));
  const Y = (v) => T + (1 - (v - ymin) / ((ymax - ymin) || 1)) * (hgt - T - B);
  const path = (arr, col, sw) => {
    const d = arr.map((v, i) => (i ? "L" : "M") + X(i).toFixed(1) + " " + Y(v).toFixed(1)).join(" ");
    return '<path d="' + d + '" fill="none" stroke="' + col + '" stroke-width="' + sw + '" vector-effect="non-scaling-stroke"/>';
  };
  let s = '<svg viewBox="0 0 ' + W + " " + hgt + '" preserveAspectRatio="none" style="width:100%;height:' + hgt + 'px;display:block;font-family:monospace;">';
  if (refVal !== null) {
    s += '<line x1="' + L + '" y1="' + Y(refVal) + '" x2="' + (W - Rp) + '" y2="' + Y(refVal) + '" stroke="#1f7a55" stroke-width="1.5" stroke-dasharray="6 4" vector-effect="non-scaling-stroke"/>';
    s += '<text x="' + (L + 4) + '" y="' + (Y(refVal) - 5) + '" font-size="11" fill="#1f7a55">' + refLabel + "</text>";
  }
  [ymin + padv, (ymin + ymax) / 2, ymax - padv].forEach((v) => {
    s += '<text x="6" y="' + (Y(v) + 4) + '" font-size="10" fill="#566173">' + yfmt(v) + "</text>";
  });
  R.forEach((r, i) => {
    if (i % 2 === 0 || i === N - 1) s += '<text x="' + X(i) + '" y="' + (hgt - 10) + '" font-size="9" fill="#566173" text-anchor="middle">' + esc(shortLabel(r.label)) + "</text>";
  });
  series.forEach((se) => { s += path(se.arr, se.col, se.sw); });
  if (hasTotal) s += '<circle cx="' + X(BASE) + '" cy="' + Y(totLine[BASE]) + '" r="5.5" fill="#1f7a55"/>';
  s += "</svg>";
  let leg = '<div style="display:flex;gap:18px;flex-wrap:wrap;font-size:12px;padding:9px 12px;border-top:1px dashed #d6dce5;">';
  series.slice().reverse().forEach((se) => { leg += '<span style="color:' + se.col + ';font-weight:700;">— ' + esc(se.name) + "</span>"; });
  leg += '<span style="color:#566173;">' + modeLabel + " · load order</span></div>";
  // Function picker sits below the graph (and its legend), not above it.
  return s + leg + pick;
}

// ---- divergence view -----------------------------------------------------
// Diverging bar chart: each function's change in self-share of total CEst (pp),
// the current run vs a reference run (the baseline run by default, or any run).
// Red = gained share, green = lost share.
function renderDiverge() {
  const { funcs, R, totals, BASE } = matrix;
  const N = R.length;
  const cur = curRun === "base" ? BASE : Math.min(curRun, N - 1);
  const latestIdx = R.reduce((best, r, i) => (r.date > R[best].date ? i : best), 0);
  const ref = cmpRun === null ? latestIdx : (cmpRun === "base" ? BASE : Math.min(parseInt(cmpRun, 10), N - 1));
  const refIsBase = cmpRun === "base";
  const refIsLatest = cmpRun === null;
  const sameRun = cur === ref;
  const shareNow = (f) => totals[cur] ? cestOf(f, cur) / totals[cur] * 100 : 0;
  const shareRef = (f) => totals[ref] ? cestOf(f, ref) / totals[ref] * 100 : 0;
  const order = funcs.map((_, f) => f).sort((a, b) => shareNow(b) - shareNow(a));
  const shown = dvgTopN === "all" ? order : order.slice(0, Math.min(dvgTopN, order.length));
  const dpp = shown.map((f) => shareNow(f) - shareRef(f));
  const maxAbs = Math.max.apply(null, dpp.map(Math.abs).concat([0])) || 1;
  function niceCeil(x) {
    if (x <= 0.5) return 0.5; if (x <= 1) return 1; if (x <= 2) return 2;
    if (x <= 3) return 3; if (x <= 5) return 5; if (x <= 6) return 6;
    if (x <= 8) return 8; if (x <= 10) return 10; return Math.ceil(x / 2) * 2;
  }
  const scale = niceCeil(maxAbs / 0.78);
  const fmtPP = (v) => (v >= 0 ? "+" : "−") + Math.abs(v).toFixed(2) + "pp";

  let sel = '<select data-currun class="dvg-sel"><option value="base"' + (curRun === "base" ? " selected" : "") + ">baseline run (auto)</option>";
  R.forEach((r, i) => { sel += '<option value="' + i + '"' + (curRun !== "base" && cur === i ? " selected" : "") + ">" + esc(r.label) + "</option>"; });
  sel += "</select>";
  let csel = '<select data-cmprun class="dvg-sel"><option value="latest"' + (cmpRun === null ? " selected" : "") + ">most recent (auto)</option>"
    + '<option value="base"' + (cmpRun === "base" ? " selected" : "") + ">baseline run (auto)</option>";
  R.forEach((r, i) => { csel += '<option value="' + i + '"' + (cmpRun !== null && cmpRun !== "base" && ref === i ? " selected" : "") + ">" + esc(r.label) + "</option>"; });
  csel += "</select>";
  const refTag = refIsBase
    ? '<span class="dvg-ref"><span class="dvg-dot"></span><span class="dvg-base">baseline run</span><span class="dvg-rid">' + esc(R[BASE].label) + "</span></span>"
    : refIsLatest
    ? '<span class="dvg-ref"><span class="dvg-dot"></span><span class="dvg-base">most recent</span><span class="dvg-rid">' + esc(R[ref].label) + "</span></span>"
    : '<span class="dvg-ref"><span class="dvg-dot man"></span><span class="dvg-rid">' + esc(R[ref].label) + "</span></span>";
  const nopt = (n) => '<option value="' + n + '"' + (dvgTopN === n ? " selected" : "") + ">top " + n + "</option>";
  const nsel = '<span class="dvg-h-lbl" style="margin-left:auto;">show</span><select data-dvgn class="dvg-sel">'
    + nopt(10) + nopt(25) + '<option value="all"' + (dvgTopN === "all" ? " selected" : "") + ">all (" + funcs.length + ")</option></select>";
  const head = '<div class="dvg-head"><span class="dvg-h-lbl">current</span>' + sel
    + '<span class="dvg-h-lbl">vs</span>' + csel + refTag + nsel
    + '<span class="dvg-leg"><span class="sw up"></span>increased<span class="sw down"></span>decreased</span></div>';

  if (sameRun) {
    return head + '<div class="dvg-foot" style="padding:26px 14px;">Current and comparison runs are the same — pick different runs to see divergence.</div>';
  }

  const ticks = [-scale, -scale / 2, 0, scale / 2, scale];
  let axis = '<div class="dvg-axis"><div class="dvg-name-sp"></div><div class="dvg-track-h">';
  ticks.forEach((t) => {
    const leftPct = 50 + (t / scale) * 50;
    axis += '<span class="dvg-tick" style="left:' + leftPct + '%">' + (t > 0 ? "+" : "") + (Math.round(t * 100) / 100) + "pp</span>";
  });
  axis += "</div></div>";

  let rowsH = "";
  shown.forEach((f, k) => {
    const d = dpp[k];
    const up = d >= 0;
    const wpct = Math.min(Math.abs(d) / scale, 1) * 50;
    const bar = '<div class="dvg-bar ' + (up ? "up" : "down") + '" style="'
      + (up ? "left:50%;" : "left:" + (50 - wpct) + "%;") + "width:" + wpct + '%"></div>';
    const dlab = up
      ? '<span class="dvg-dpp up" style="left:' + (50 + wpct) + '%;">' + fmtPP(d) + "</span>"
      : '<span class="dvg-dpp down" style="left:' + (50 - wpct) + '%;transform:translateX(-100%);">' + fmtPP(d) + "</span>";
    const trans = up
      ? '<span class="dvg-trans" style="left:50%;transform:translateX(-100%);">' + shareNow(f).toFixed(2) + "% ← " + shareRef(f).toFixed(2) + "%</span>"
      : '<span class="dvg-trans" style="left:50%;">' + shareNow(f).toFixed(2) + "% ← " + shareRef(f).toFixed(2) + "%</span>";
    rowsH += '<div class="dvg-row"><div class="dvg-name" title="' + esc(funcs[f]) + '">' + esc(funcs[f]) + "</div>"
      + '<div class="dvg-track"><span class="dvg-center"></span>' + bar + dlab + trans + "</div></div>";
  });

  const refLabel = refIsBase ? "baseline run" : refIsLatest ? "most recent run" : ("run " + esc(R[ref].label));
  const countLabel = (dvgTopN === "all" || shown.length >= funcs.length)
    ? ("all " + funcs.length + " functions")
    : ("top " + shown.length + " of " + funcs.length + " functions, by current share");
  return head + axis + '<div class="dvg-rows">' + rowsH + "</div>"
    + '<div class="dvg-foot">Δ self-share in percentage points (pp) · current run vs ' + refLabel + " · " + countLabel + "</div>";
}

// ---- mutations -----------------------------------------------------------
function removeRun(i) {
  runs.splice(i, 1);
  compareSel = [];    // run indices shift; drop the compare selection
  compareRuns = null;
  costRun = null;     // run indices shift; drop the focused cost view
  // Removing a run re-parses the remaining set — no reading phase, just analysis.
  if (runs.length >= LOADING_MIN_RUNS) { setPhaseList(["Analyzing"]); setActivePhase(0); }
  analyze();
}
function clearRuns() {
  runs = [];
  full = null;
  matrix = null;
  compareSel = [];
  compareRuns = null;
  baseRun = 0;
  baseRunPinned = false; // fresh set: baseline returns to the default
  costRun = null;
  hideError();
  render();
}

// ---- hosted-store picker -------------------------------------------------
const repoRowsEl   = $("repo-rows");
const repoSearchEl = $("repo-search");
const repoTickedEl = $("repo-ticked");
const repoAddBtn   = $("repo-add");
const repoAllEl    = $("repo-all");

// parsePathParts splits a store run path. A valid result is exactly
// <branch>/<sha>/<run>/<suite>/<test> (5 segments); archived trees carry an
// extra "archive-..." segment (6+) and are rejected (null) so they are not
// selectable. manifest.json's own branch/sha/run fields split from the START,
// which mis-aligns on those archived trees, so we parse the path ourselves.
function parsePathParts(path) {
  const s = String(path).split("/");
  if (s.length !== 5) return null;
  return { branch: s[0], sha: s[1], run: s[2], suite: s[3], test: s[4] };
}

function fmtStoreDate(epoch) {
  const d = new Date((Number(epoch) || 0) * 1000);
  if (isNaN(d.getTime())) return "—";
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

// ledgerKey joins a store run to its publish entry in run-index-map.json.
function ledgerKey(branch, sha, run, suite, test) {
  return [branch, sha, run, suite, test].join(" ");
}

// fetchStoreManifest pulls the store manifest (and, best-effort, the run-index
// ledger) and builds storeRuns + storeLedger. Runs each time the modal opens so
// freshly published runs appear. Paints a loading / error state in the table.
async function fetchStoreManifest() {
  repoRowsEl.innerHTML = '<tr><td colspan="8"><div class="runs-empty">Loading runs from ' + esc(store.label) + "…</div></td></tr>";
  repoSearchEl.disabled = true;
  repoShown = []; updateRepoAll();   // no selectable rows while loading/on error
  let manifest;
  try {
    const resp = await fetch(store.url + "/manifest.json", { cache: "no-store" });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    manifest = await resp.json();
  } catch (e) {
    repoRowsEl.innerHTML = '<tr><td colspan="8"><div class="runs-empty">Could not load runs from <code>'
      + esc(store.url) + "/manifest.json</code> (" + esc(String(e.message || e))
      + "). The store may be unreachable.</div></td></tr>";
    return;
  }
  // The ledger is optional (absent until a publish writes it); failure is silent.
  storeLedger = {};
  try {
    const lr = await fetch(store.url + "/run-index-map.json", { cache: "no-store" });
    if (lr.ok) {
      const ledger = await lr.json();
      (ledger.publishes || []).forEach((p) => {
        (p.index_map || []).forEach((m) => {
          storeLedger[ledgerKey(p.branch, p.sha, m.store_run_index, m.suite, m.test)] =
            { number: p.github_run_number, runId: p.github_run_id, repo: p.github_repository };
        });
      });
    }
  } catch (e) { /* no ledger — the by/PR column shows — */ }

  storeRuns = (manifest.runs || []).map((r) => {
    const parts = parsePathParts(r.path);
    if (!parts) return null;
    const cgFiles = (r.files || []).filter((n) => n.indexOf("callgrind.out") === 0);
    if (cgFiles.length === 0) return null; // no callgrind data -> nothing to analyze
    return { path: r.path, date: r.date || 0, bytes: r.bytes || 0, cgFiles, ...parts };
  }).filter(Boolean);
  // Newest first; ties broken by sha then numeric run for a stable order.
  storeRuns.sort((a, b) => (b.date - a.date)
    || (a.sha < b.sha ? -1 : a.sha > b.sha ? 1 : 0)
    || (parseInt(a.run, 10) - parseInt(b.run, 10)));
  repoSearchEl.disabled = false;
  renderRepoRows();
}

// runMatchesSearch: AND over space-separated terms across the run's fields.
function runMatchesSearch(r, terms) {
  if (!terms.length) return true;
  const led = storeLedger[ledgerKey(r.branch, r.sha, r.run, r.suite, r.test)];
  const hay = (r.branch + " " + r.sha + " " + r.run + " " + r.suite + " " + r.test
    + (led && led.number != null ? " #" + led.number : "")).toLowerCase();
  return terms.every((t) => hay.includes(t));
}

function renderRepoRows() {
  const terms = repoSearchEl.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  repoShown = storeRuns.filter((r) => runMatchesSearch(r, terms));
  repoShown.sort(repoCmp);
  if (storeRuns.length === 0) {
    repoRowsEl.innerHTML = '<tr><td colspan="8"><div class="runs-empty">No analyzable runs on the store yet.</div></td></tr>';
  } else if (repoShown.length === 0) {
    repoRowsEl.innerHTML = '<tr><td colspan="8"><div class="runs-empty">No runs match "'
      + esc(repoSearchEl.value.trim()) + '".</div></td></tr>';
  } else {
    repoRowsEl.innerHTML = repoShown.map((r) => {
      const led = storeLedger[ledgerKey(r.branch, r.sha, r.run, r.suite, r.test)];
      const by = (led && led.repo && led.runId != null)
        ? '<a href="https://github.com/' + esc(led.repo) + "/actions/runs/" + esc(led.runId)
          + '" target="_blank" rel="noopener">#' + esc(led.number != null ? led.number : "run") + "</a>"
        : "—";
      const checked = repoTicked.has(r.path) ? " checked" : "";
      return '<tr><td><input type="checkbox" data-runpath="' + esc(r.path) + '"' + checked + " /></td>"
        + "<td>" + esc(fmtStoreDate(r.date)) + "</td>"
        + '<td class="mono">' + esc(r.sha) + "</td>"
        + "<td>" + esc(r.branch) + "</td>"
        + '<td class="mono">' + esc(r.run) + "</td>"
        + "<td>" + esc(r.suite) + "</td>"
        + "<td>" + esc(r.test) + "</td>"
        + "<td>" + by + "</td></tr>";
    }).join("");
  }
  updateRepoFoot();
  updateRepoAll();
  updateRepoSortHeaders();
}

function updateRepoFoot() {
  repoTickedEl.textContent = repoTicked.size + " ticked";
  repoAddBtn.disabled = repoTicked.size === 0;
}

// updateRepoAll syncs the header "select all" box to the shown rows: checked
// when every shown run is ticked, indeterminate when only some are, disabled
// when nothing is shown.
function updateRepoAll() {
  const n = repoShown.length;
  const t = repoShown.reduce((acc, r) => acc + (repoTicked.has(r.path) ? 1 : 0), 0);
  repoAllEl.disabled = n === 0;
  repoAllEl.checked = n > 0 && t === n;
  repoAllEl.indeterminate = t > 0 && t < n;
}

// repoGhNumber: the GitHub run number joined from the ledger, or -1 if absent
// (so runs with no ledger entry sort to the bottom ascending / top descending).
function repoGhNumber(r) {
  const led = storeLedger[ledgerKey(r.branch, r.sha, r.run, r.suite, r.test)];
  return led && led.number != null ? led.number : -1;
}

// repoCmp orders runs by the active picker column (repoSort): date/run/by
// numerically, the rest lexically, with a stable path tiebreaker so equal keys
// keep a deterministic order.
function repoCmp(a, b) {
  const k = repoSort.key, s = repoSort.dir === "asc" ? 1 : -1;
  let d;
  if (k === "date") d = a.date - b.date;
  else if (k === "run") d = (parseInt(a.run, 10) || 0) - (parseInt(b.run, 10) || 0);
  else if (k === "by") d = repoGhNumber(a) - repoGhNumber(b);
  else d = String(a[k]).localeCompare(String(b[k])); // sha, branch, suite, test
  if (d) return s * d;
  return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
}

// updateRepoSortHeaders paints the active-column arrow on the picker headers.
function updateRepoSortHeaders() {
  document.querySelectorAll("#repo-modal th.sortable").forEach((th) => {
    const active = th.getAttribute("data-sort") === repoSort.key;
    th.classList.toggle("on", active);
    const arr = th.querySelector(".rarr");
    if (arr) arr.textContent = active ? (repoSort.dir === "asc" ? "▲" : "▼") : "";
  });
}

// addRunsFromStore fetches the callgrind.out.* files for each ticked run and
// loads them as runs, mirroring the local pick's progress bar. Labelled
// <sha>/<run>/<suite>/<test> so cross-commit comparisons stay distinguishable.
async function addRunsFromStore(paths) {
  const picks = paths.map((p) => storeRuns.find((r) => r.path === p)).filter(Boolean);
  if (picks.length === 0) return;
  closeRepoModal();
  setPhaseList(["Fetching files", "Analyzing"]); setActivePhase(0);
  let failed = 0;
  for (let i = 0; i < picks.length; i++) {
    const r = picks[i];
    showLoading("Fetching run " + (i + 1) + " of " + picks.length + "…", (i + 1) / picks.length);
    await yieldToPaint();
    const filesObj = {};
    try {
      await Promise.all(r.cgFiles.map(async (name) => {
        const resp = await fetch(store.url + "/" + r.path + "/" + name, { cache: "no-store" });
        if (!resp.ok) throw new Error(name + ": HTTP " + resp.status);
        filesObj[name] = await resp.text();
      }));
    } catch (e) {
      failed++;
      showError("Failed to fetch " + r.path + " (" + (e.message || e) + ")");
      continue;
    }
    // `path` is the store path this run came from; it's what the shareable URL
    // records so the run can be re-fetched on open. Local picks have no path, so
    // a run set containing any of them is not shareable (see syncURL).
    runs.push({ label: uniqueLabel(r.sha + "/" + r.run + "/" + r.suite + "/" + r.test), files: filesObj, date: r.date || 0, path: r.path });
  }
  setActivePhase(1);
  if (!failed) hideError();
  repoTicked.clear();
  // forceProg so the analyze bar always paints under the stepper (the store path
  // shows the stepper unconditionally), matching the local pick.
  await analyze({ forceProg: true });
}

// ---- events --------------------------------------------------------------
// Source choice: local files (default) or the hosted prof-results store. The
// store path opens the selection modal, which fetches the store manifest.
let source = "repo";
const srcseg = $("srcseg");
const repoModal = $("repo-modal");
// The import filter only applies to a local-files pick; the Repo picker has its
// own search box. Hide the field when the Repo source is selected so it is clear
// it does not apply there.
function updateSourceUI() { importFilterInput.disabled = source === "repo"; }

srcseg.addEventListener("click", (e) => {
  const b = e.target.closest("button[data-src]");
  if (!b) return;
  source = b.dataset.src;
  srcseg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
  updateSourceUI();
});
updateSourceUI(); // set initial visibility for the default (repo) source

function openRepoModal() { repoModal.classList.add("on"); fetchStoreManifest(); }
function closeRepoModal() { repoModal.classList.remove("on"); }
$("repo-cancel").addEventListener("click", closeRepoModal);
repoModal.addEventListener("click", (e) => { if (e.target === repoModal) closeRepoModal(); });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && repoModal.classList.contains("on")) closeRepoModal();
});
// Search filters the rendered rows; ticking updates the count + Add button.
repoSearchEl.addEventListener("input", renderRepoRows);
repoRowsEl.addEventListener("change", (e) => {
  const cb = e.target.closest("[data-runpath]");
  if (!cb) return;
  const p = cb.getAttribute("data-runpath");
  if (cb.checked) repoTicked.add(p); else repoTicked.delete(p);
  updateRepoFoot();
  updateRepoAll();
});
// Header box ticks/clears every run currently shown under the filter.
repoAllEl.addEventListener("change", () => {
  repoShown.forEach((r) => { if (repoAllEl.checked) repoTicked.add(r.path); else repoTicked.delete(r.path); });
  renderRepoRows();
});
// Click a column header to sort; clicking the active column flips direction.
repoModal.addEventListener("click", (e) => {
  const th = e.target.closest("th.sortable");
  if (!th) return;
  const col = th.getAttribute("data-sort");
  if (repoSort.key === col) repoSort.dir = repoSort.dir === "asc" ? "desc" : "asc";
  else repoSort = { key: col, dir: (col === "date" || col === "by") ? "desc" : "asc" };
  renderRepoRows();
});
repoAddBtn.addEventListener("click", () => addRunsFromStore([...repoTicked]));

addRunsBtn.addEventListener("click", () => {
  if (source === "repo") openRepoModal();
  else dirInput.click();
});
// Enter in the import filter opens the picker (same as clicking Add runs).
importFilterInput.addEventListener("keydown", (e) => { if (e.key === "Enter") addRunsBtn.click(); });
dirInput.addEventListener("change", async (e) => {
  const fl = e.target.files;
  if (fl && fl.length) await addRunsFromPick(fl);
  dirInput.value = ""; // allow re-picking the same directory
});
clearBtn.addEventListener("click", clearRuns);

viewseg.addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-view]");
  if (!btn || btn.disabled) return;
  view = btn.dataset.view;
  // Selecting a comparison view leaves the per-run detail and the compare views
  // (the compare selection stays, so "Compare Selected" can re-open it).
  detailRun = null;
  detailData = null;
  compareRuns = null;
  viewseg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b === btn));
  render();
});
valseg.addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-val]");
  if (!btn) return;
  valMode = btn.dataset.val;
  valseg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b === btn));
  render();
});
// The functions count and patterns filter both only re-slice the cached matrix
// (no re-parse). Debounce so typing/spinning stays responsive; Enter commits now.
let applyTimer = null;
function scheduleApply() { clearTimeout(applyTimer); applyTimer = setTimeout(applyTopN, 250); }
function commitApply() { clearTimeout(applyTimer); applyTopN(); }
topnInput.addEventListener("input", scheduleApply);
topnInput.addEventListener("keydown", (e) => { if (e.key === "Enter") commitApply(); });
// "view" selector: all-runs change view (null) or focus one run's cost heatmap.
if (focusRunSel) {
  focusRunSel.addEventListener("change", () => {
    costRun = focusRunSel.value === "all" ? null : parseInt(focusRunSel.value, 10);
    render();
  });
}
patternsInput.addEventListener("input", scheduleApply);
patternsInput.addEventListener("keydown", (e) => { if (e.key === "Enter") commitApply(); });
// Fold changes the underlying self-costs, so it re-parses every run (unlike the
// display-only patterns/top-N, which only re-slice the cached matrix). A full
// re-parse is too expensive to run on each keystroke, so fold applies ONLY when
// the user presses Enter in the box or clicks Fold; typing just marks the
// button dirty so it is clear the typed value is not live yet.
let lastFoldKey = "";
function applyFold() {
  const key = foldInput ? foldInput.value.trim() : "";
  lastFoldKey = key;
  if (foldApplyBtn) foldApplyBtn.classList.remove("dirty");
  if (!runs.length) return;
  // Folding re-parses every run, so always show a "Folding" pill for feedback
  // (forceProg), even with few runs — unlike the add/remove "Analyzing" pill,
  // which is gated on LOADING_MIN_RUNS.
  setPhaseList(["Folding"]); setActivePhase(0);
  setFoldList(foldPaths()); // list the full paths being folded under the pill
  analyze({ verb: "Folding", forceProg: true });
}
if (foldInput) {
  foldInput.addEventListener("input", () => {
    if (foldApplyBtn) foldApplyBtn.classList.toggle("dirty", foldInput.value.trim() !== lastFoldKey);
  });
  foldInput.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); applyFold(); } });
}
if (foldApplyBtn) foldApplyBtn.addEventListener("click", applyFold);
// "reset fold list" (rendered inside the applied-fold list under the chips):
// empty the box and re-parse unfolded so the matrix drops every fold.
function resetFold() {
  if (foldInput) foldInput.value = "";
  if (!runs.length) { lastFoldKey = ""; appliedFoldPaths = []; renderAppliedFold(); return; }
  applyFold(); // reads the now-empty box → foldPaths() = [] → re-parses unfolded
}
if (appliedFoldEl) {
  appliedFoldEl.addEventListener("click", (e) => { if (e.target.closest(".af-reset")) resetFold(); });
}
// The heatmap highlight thresholds live in the legend (#regress-thresh /
// #improve-thresh), which render() rebuilds each pass. Update on input and
// repaint ONLY the heatmap cells (not the whole legend), so the edited input
// keeps focus while the user is typing in it.
nlegendEl.addEventListener("input", (e) => {
  const id = e.target.id;
  const liveHeat = matrix && view === "heat" && detailRun === null && compareRuns === null;
  if (id === "regress-thresh" || id === "improve-thresh") {
    const v = Math.max(0, Math.min(100, parseInt(e.target.value, 10) || 0));
    if (id === "regress-thresh") regressMin = v; else improveMin = v;
    if (liveHeat) nviewEl.innerHTML = renderHeat();
  } else if (id === "hotcolor" || id === "bestcolor") {
    if (id === "hotcolor") hotColor = e.target.value; else bestColor = e.target.value;
    if (liveHeat) nviewEl.innerHTML = renderHeat();
  }
});
// Overflow menu: column order (heatmap only) + Download JSON.
function syncMenu() {
  menu.querySelectorAll("[data-order]").forEach((b) => b.classList.toggle("on", b.dataset.order === orderMode));
  const mo = $("menu-order");
  // Column order only affects the multi-run heatmap — hide it in detail/compare
  // views and for a single run (the cost view has no run columns to reorder).
  if (mo) mo.hidden = view !== "heat" || detailRun !== null || compareRuns !== null || runs.length < 2 || costRun !== null;
}
function setMenu(open) { menu.hidden = !open; menuBtn.setAttribute("aria-expanded", String(open)); }
menuBtn.addEventListener("click", (e) => { e.stopPropagation(); setMenu(menu.hidden); });
document.addEventListener("click", (e) => { if (!menu.hidden && !e.target.closest(".menu-wrap")) setMenu(false); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !menu.hidden) setMenu(false); });
menu.addEventListener("click", (e) => {
  const ord = e.target.closest("[data-order]");
  if (ord) {
    orderMode = ord.dataset.order;
    // The default baseline depends on the order (oldest for date), so re-pick it
    // unless the user pinned a baseline.
    if (!baseRunPinned && full) {
      baseRun = defaultBaseRun(full.R); full.BASE = baseRun;
      if (matrix) matrix.BASE = baseRun;
    }
    setMenu(false); if (matrix) render(); return;
  }
  if (e.target.closest("#menu-download")) { setMenu(false); if (compareRuns) downloadCompareJson(); else downloadJson(); }
});

// The divergence selectors and the trends function picker live inside the
// re-rendered view, so listen via delegation on the view container.
nviewEl.addEventListener("change", (e) => {
  const cc = e.target.closest("[data-currun]");
  if (cc) { curRun = cc.value === "base" ? "base" : parseInt(cc.value, 10); render(); return; }
  const cr = e.target.closest("[data-cmprun]");
  if (cr) { cmpRun = cr.value === "latest" ? null : (cr.value === "base" ? "base" : parseInt(cr.value, 10)); render(); return; }
  const cn = e.target.closest("[data-dvgn]");
  if (cn) { dvgTopN = cn.value === "all" ? "all" : parseInt(cn.value, 10); render(); return; }
  const ctn = e.target.closest("[data-cmp-topn]");
  if (ctn) { compareTopN = ctn.value === "all" ? "all" : parseInt(ctn.value, 10); render(); return; }
});
nviewEl.addEventListener("click", (e) => {
  // Single-run cost heatmap: click a column header to sort, again to flip.
  const costH = e.target.closest("[data-costsort]");
  if (costH) {
    const key = costH.getAttribute("data-costsort");
    if (costSort.key === key) costSort.dir = costSort.dir === "asc" ? "desc" : "asc";
    else costSort = { key, dir: key === "name" ? "asc" : "desc" };
    render();
    return;
  }
  // Heatmap: a run's column header opens that run's detail view.
  const rc = e.target.closest("[data-runcol]");
  if (rc) { openDetail(parseInt(rc.getAttribute("data-runcol"), 10)); return; }
  // Compare view: Back, and the sortable headers.
  if (e.target.closest("[data-cmp-back]")) { compareRuns = null; render(); return; }
  const cs = e.target.closest("[data-cmpsort]");
  if (cs) {
    const key = cs.getAttribute("data-cmpsort");
    const norm = (key === "name" || key === "spread") ? key : parseInt(key, 10);
    if (String(compareSort.key) === key) compareSort.dir = compareSort.dir === "asc" ? "desc" : "asc";
    else compareSort = { key: norm, dir: key === "name" ? "asc" : "desc" };
    render();
    return;
  }
  // Detail view: the "Back" button and the sortable column headers.
  if (e.target.closest("[data-detail-back]")) { closeDetail(); return; }
  const sh = e.target.closest("[data-sorttable]");
  if (sh) {
    const sort = sh.getAttribute("data-sorttable") === "pat" ? detailPatSort : detailFnSort;
    const col = sh.getAttribute("data-sortcol");
    // Clicking the active column flips direction; a new column starts on its
    // natural default (names A→Z, counters high→low).
    if (sort.key === col) sort.dir = sort.dir === "asc" ? "desc" : "asc";
    else { sort.key = col; sort.dir = col === "name" ? "asc" : "desc"; }
    render();
    return;
  }
  const tf = e.target.closest("[data-trendfn]");
  if (!tf || tf.classList.contains("dis")) return;
  const f = parseInt(tf.getAttribute("data-trendfn"), 10);
  if (trendFns === null) trendFns = [];
  const idx = trendFns.indexOf(f);
  if (idx >= 0) trendFns.splice(idx, 1);
  else if (trendFns.length < 5) trendFns.push(f);
  render();
});

// Compare action bar: open the compare view, go back, or clear the selection.
$("cmp-bar").addEventListener("click", (e) => {
  if (e.target.closest("[data-cmp-go]")) {
    if (compareSel.length >= 2) { detailRun = null; detailData = null; compareRuns = compareSel.slice(); render(); }
    return;
  }
  if (e.target.closest("[data-cmp-back]")) { compareRuns = null; render(); return; }
  if (e.target.closest("[data-cmp-clear]")) { compareSel = []; compareRuns = null; render(); return; }
});

// The trends SVG is sized to the view width; re-render (debounced) on resize.
let resizeTimer = null;
window.addEventListener("resize", () => {
  if (!matrix || view !== "trend") return;
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(render, 120);
});

// ---- copy fold path (hover popover) --------------------------------------
// Hovering a function name in the heatmap / detail views opens a small popover
// listing that node's full root-first call paths (from full.pathsByFn, set by
// parseRuns). Clicking a path copies it to the clipboard for pasting into the
// fold box. A copy needs a click gesture, so hover only reveals the choices.
function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}
function fallbackCopy(text) { // non-secure contexts (e.g. http://<ip>) lack navigator.clipboard
  const ta = document.createElement("textarea");
  ta.value = text; ta.style.position = "fixed"; ta.style.top = "-1000px"; ta.style.opacity = "0";
  document.body.appendChild(ta); ta.focus(); ta.select();
  try { document.execCommand("copy"); } catch (_) { /* best effort */ }
  document.body.removeChild(ta);
}
let copyToastTimer = null;
function showCopyToast(msg) {
  let t = $("copytoast");
  if (!t) { t = document.createElement("div"); t.id = "copytoast"; t.className = "copytoast"; document.body.appendChild(t); }
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(copyToastTimer);
  copyToastTimer = setTimeout(() => t.classList.remove("show"), 1500);
}

const fpPop = document.createElement("div");
fpPop.className = "fp-pop"; fpPop.hidden = true;
document.body.appendChild(fpPop);
let fpOpenFn = null, fpAnchorEl = null, fpCloseTimer = null;
function fpCancelClose() { clearTimeout(fpCloseTimer); }
function fpScheduleClose() { clearTimeout(fpCloseTimer); fpCloseTimer = setTimeout(fpClose, 180); }
function fpClose() { fpPop.hidden = true; fpPop.innerHTML = ""; fpOpenFn = null; fpAnchorEl = null; }
// fpOptionsFor builds the list shown for a function: its specific call paths
// (most costly first) plus an "all calls" entry that folds every call of it.
function fpOptionsFor(fn) {
  const out = [];
  const ps = (full && full.pathsByFn && full.pathsByFn[fn]) || [];
  ps.forEach((pc) => out.push({ copy: pc.p, note: fmtM(pc.c) }));
  out.push({ copy: fn, all: true });
  return out;
}
// fpReposition anchors the popover under its name (fixed coords), flipping above
// if it would clip. Reused on scroll so the popover tracks the name instead of
// vanishing - the detail view is a nested scroll container, so closing on scroll
// made the popover feel like it never appeared.
function fpReposition() {
  if (fpPop.hidden || !fpAnchorEl) return;
  if (!fpAnchorEl.isConnected) { fpClose(); return; }
  const r = fpAnchorEl.getBoundingClientRect();
  if (r.bottom < 0 || r.top > window.innerHeight) { fpClose(); return; } // scrolled out of view
  const pw = fpPop.offsetWidth, ph = fpPop.offsetHeight;
  let left = r.left, top = r.bottom + 4;
  if (left + pw > window.innerWidth - 8) left = window.innerWidth - 8 - pw;
  if (top + ph > window.innerHeight - 8) top = r.top - 4 - ph;
  fpPop.style.left = Math.max(8, left) + "px";
  fpPop.style.top = Math.max(8, top) + "px";
}
function fpOpen(anchor, fn) {
  if (fpOpenFn === fn && !fpPop.hidden) { fpCancelClose(); return; }
  const opts = fpOptionsFor(fn);
  const hasPaths = opts.some((o) => !o.all);
  fpPop.innerHTML = '<div class="fp-head">'
      + (hasPaths ? "copy a call path to fold" : "no separate-caller path · copy name to fold all calls")
      + "</div>"
    + opts.map((o) => '<button type="button" class="fp-opt' + (o.all ? " fp-all" : "") + '" data-copy="' + esc(o.copy) + '">'
        + '<span class="fp-path">' + esc(o.all ? (fn + "  — all calls") : o.copy) + "</span>"
        + (o.note ? '<span class="fp-cest">' + o.note + "</span>" : "")
        + "</button>").join("");
  fpPop.hidden = false;
  fpOpenFn = fn; fpAnchorEl = anchor;
  fpReposition();
  fpCancelClose();
}
nviewEl.addEventListener("mouseover", (e) => {
  const el = e.target.closest(".copyfn");
  if (el && el.dataset.fn) { fpCancelClose(); fpOpen(el, el.dataset.fn); }
});
nviewEl.addEventListener("mouseout", (e) => {
  if (e.target.closest(".copyfn")) fpScheduleClose();
});
fpPop.addEventListener("mouseenter", fpCancelClose);
fpPop.addEventListener("mouseleave", fpScheduleClose);
fpPop.addEventListener("click", (e) => {
  const btn = e.target.closest(".fp-opt");
  if (!btn) return;
  copyText(btn.dataset.copy);
  showCopyToast("Copied: " + btn.dataset.copy);
  fpClose();
});
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !fpPop.hidden) fpClose(); });
// Keep the popover glued to its name as any container scrolls (capture catches
// the nested detail-scroll), repositioning rather than closing.
window.addEventListener("scroll", fpReposition, true);
window.addEventListener("resize", fpReposition);

// ---- misc ----------------------------------------------------------------
function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
// ---- download -----------------------------------------------------------
// Same Blob + anchor mechanism as v1. Exports the complete comparison dataset
// (all functions, every run's CEst, totals, the baseline run) — not just the
// displayed top-N — so the file is the full analysis, independent of the view.
function download(content, type, filename) {
  if (!content) return;
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
function downloadJson() {
  if (!full || !wasmReady) return;
  // Match the heatmap's "functions" cap: empty / non-positive exports all (the
  // shared-set size is a safe upper bound that the report caps to per run).
  const raw = parseInt(topnInput.value, 10);
  const topN = (isNaN(raw) || raw <= 0) ? full.funcs.length : raw;
  const runsObj = {};
  runs.forEach((r) => { runsObj[r.label] = r.files; });
  const pats = patternsInput.value.trim().split(/\s+/).filter(Boolean);
  const res = cestReport(runsObj, topN, pats); // rich report schema (all 9 counters)
  if (res.error) { showError(res.error); return; }
  download(res.json, "application/json", "cest-compare.json");
}
// downloadJson is triggered from the overflow menu (#menu-download), not a
// standalone button.

// downloadCompareJson exports the compare view's data: the selected runs and,
// per function, CEst per run, the lowest-CEst (best) run, Δ% vs best per run,
// and the spread. All functions (patterns-filtered), sorted like the table
// (spread desc, 'new' last) — not capped by the functions selector.
function downloadCompareJson() {
  if (!compareRuns || !full) return;
  ensureCompareData();
  if (!compareData) return;
  const sel = compareRuns, R = full.R;
  const pats = patternsInput.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  // Use the Go-computed rows (already spread-desc, 'new' last); JS only filters
  // by patterns and shapes the labels — no compare math here.
  const rows = pats.length
    ? compareData.filter((r) => { const l = r.name.toLowerCase(); return pats.some((p) => l.includes(p)); })
    : compareData;

  const functions = rows.map((r) => {
    const cest = {}, deltaPctVsBest = {};
    sel.forEach((ri, k) => {
      cest[R[ri].label] = r.cest[k];
      deltaPctVsBest[R[ri].label] = isFinite(r.deltaPct[k]) ? r.deltaPct[k] : null; // null where a run lacks it
    });
    return {
      name: r.name, cest, deltaPctVsBest,
      best: R[sel[r.best]].label,
      spreadPct: isFinite(r.spreadPct) ? r.spreadPct : null, // null = a run lacks this function
    };
  });

  const out = {
    schema: "cest-compare-1",
    baseline: "per-function lowest-CEst run",
    runs: sel.map((ri) => ({ label: R[ri].label, totalCEst: R[ri].total })),
    functions,
  };
  download(JSON.stringify(out, null, 2), "application/json", "cest-compare-runs.json");
}

function showError(msg) { errorP.textContent = msg; errorP.hidden = false; }
function hideError() { errorP.hidden = true; errorP.textContent = ""; }

// ---- shareable URL -------------------------------------------------------
// The current view is mirrored into location.hash (#s=<base64url(JSON)>) so the
// address-bar URL is always copy-able: opening it re-fetches the same runs from
// the store and reconstructs the same view. Only repo-sourced runs can be
// reconstructed (a URL can't reference a local file pick), so a run set with any
// local pick is not shareable and the hash is cleared instead.

// UTF-8-safe base64url (handles non-ASCII in patterns/fold without deprecated
// escape/unescape).
function b64urlEncode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(b64) {
  let s = b64.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "="; // restore stripped padding (atob needs it)
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

// captureState builds the compact state object. Keys are short to keep URLs
// small; only non-default values are stored, so a plain heatmap of a few runs
// yields a short link. Run-index / function-index fields (bs/co/cm/tf/...) are
// positions into the run list `r` and the parsed function set, both deterministic
// given the same runs + fold + patterns, so they survive a reload.
function captureState() {
  const s = { v: 1, r: runs.map((x) => x.path), vw: view, vl: valMode, od: orderMode };
  if (baseRunPinned) s.bs = baseRun;
  if (costRun !== null) s.co = costRun;
  if (compareSel.length) s.cm = compareSel.slice();
  if (compareRuns) s.cmo = 1;
  if (compareTopN !== "all") s.cmn = compareTopN;
  if (compareSort.key !== "spread" || compareSort.dir !== "desc") s.cms = { k: compareSort.key, d: compareSort.dir };
  if (trendFns && trendFns.length) s.tf = trendFns.slice();
  if (curRun !== "base") s.dc = curRun;
  if (cmpRun !== null) s.dr = cmpRun;
  if (dvgTopN !== 10) s.dn = dvgTopN;
  if (detailRun !== null) s.dt = detailRun;
  const tn = topnInput.value.trim();      if (tn) s.tn = tn;
  const pt = patternsInput.value.trim();  if (pt) s.pt = pt;
  const fd = foldInput ? foldInput.value.trim() : ""; if (fd) s.fd = fd;
  if (regressMin !== 5) s.rm = regressMin;
  if (improveMin !== 5) s.im = improveMin;
  if (hotColor !== "#b42318") s.hc = hotColor;
  if (bestColor !== "#ffffff") s.bc = bestColor;
  return s;
}

function syncURL() {
  if (restoring) return; // don't clobber the hash while we're reading/replaying it
  const shareable = runs.length > 0 && runs.every((x) => x.path);
  const hash = shareable ? "#s=" + b64urlEncode(JSON.stringify(captureState())) : "";
  if (location.hash !== hash) {
    history.replaceState(null, "", location.pathname + location.search + hash);
  }
}

function setSegOn(seg, attr, val) {
  if (seg) seg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.getAttribute(attr) === val));
}

// doRestore replays a decoded state: apply the config the load reads (fold,
// patterns, cap, baseline, order, view), fetch the runs from the store, then
// re-apply the index-based selections that parseRuns() resets. Indices are
// clamped to what actually loaded, so a since-removed store run degrades
// gracefully instead of throwing.
async function doRestore(st) {
  try {
    await wasmReadyP;
    await configReadyP;
    if (st.vw) { view = st.vw; setSegOn(viewseg, "data-view", view); }
    if (st.vl) { valMode = st.vl; setSegOn(valseg, "data-val", valMode); }
    if (st.od) orderMode = st.od;
    if (st.tn != null) topnInput.value = st.tn;
    if (st.pt != null) patternsInput.value = st.pt;
    if (st.fd != null && foldInput) { foldInput.value = st.fd; lastFoldKey = st.fd; }
    if (st.rm != null) regressMin = st.rm;
    if (st.im != null) improveMin = st.im;
    if (st.hc) hotColor = st.hc;
    if (st.bc) bestColor = st.bc;
    if (st.bs != null) { baseRun = st.bs; baseRunPinned = true; }

    source = "repo";
    await fetchStoreManifest();   // populate storeRuns (needs store.url from config)
    await addRunsFromStore(st.r); // fetch files + analyze + render (restoring guard holds the hash)
    if (runs.length === 0) {
      showError("Couldn't load the shared runs (" + st.r.length + " requested) — they may have been removed from the store, or the store is unreachable.");
    }

    const N = runs.length;
    const F = matrix ? matrix.funcs.length : 0;
    if (st.co != null && st.co < N) costRun = st.co;
    if (Array.isArray(st.cm)) compareSel = st.cm.filter((i) => i < N);
    if (st.cmo && compareSel.length >= 2) compareRuns = compareSel.slice();
    if (st.cmn != null) compareTopN = st.cmn;
    if (st.cms && st.cms.k != null) compareSort = { key: st.cms.k, dir: st.cms.d || "desc" };
    if (Array.isArray(st.tf)) { const t = st.tf.filter((f) => f < F); trendFns = t.length ? t : null; }
    if (st.dc != null) curRun = st.dc;
    if (st.dr != null) cmpRun = st.dr;
    if (st.dn != null) dvgTopN = st.dn;
  } catch (e) {
    showError("Couldn't fully restore the shared view: " + (e.message || e));
  } finally {
    restoring = false;
    // The detail view needs its own parse; openDetail() fetches + renders. Any
    // other view just renders (which now writes the final, normalized hash).
    if (st && st.dt != null && st.dt < runs.length) openDetail(st.dt);
    else render();
  }
}

// restoreFromURL kicks off a restore if the hash carries valid state. Returns
// true if it did (so the caller skips the plain initial render). Sets `restoring`
// synchronously first, so the shell render() below won't clear the hash we're
// about to read.
function restoreFromURL() {
  const m = location.hash.match(/^#s=(.+)$/);
  if (!m) return false;
  let st = null;
  try { st = JSON.parse(b64urlDecode(m[1])); } catch (e) { return false; }
  if (!st || !Array.isArray(st.r) || st.r.length === 0) return false;
  restoring = true;
  render();      // paint the empty shell while runs load; restoring guard holds the hash
  doRestore(st); // async; fire and forget
  return true;
}

// On load: replay a shared link if present, else paint the initial empty state.
if (!restoreFromURL()) render();
