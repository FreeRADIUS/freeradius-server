// app.js — CEst compare UI (v2).
//
// Loads the shared WASM core (../v1/cest-analyzer.wasm) and calls the
// cestMatrix(runs, topN) bridge to get a complete function×run matrix, then
// renders the comparison views. Phase 1: local directory loading + the heatmap
// view (p50-median baseline, Δ%/absolute, threshold, ordering). Trends and
// divergence views are added next.
//
// A "run" is one directory of callgrind.out.* files (one test directory in the
// prof-results tree). Everything runs locally in the browser; no file is sent.

"use strict";

const $ = (id) => document.getElementById(id);

const addRunsBtn = $("add-runs");
const clearBtn   = $("clear-runs");
const dirInput   = $("dir-input");
const chipsEl     = $("chips");
const emptyHint  = $("empty-hint");
const controlsEl = $("controls");
const viewseg    = $("viewseg");
const valseg     = $("valseg");
const topnInput  = $("topn");
const patternsInput = $("patterns");
const nthreshInp = $("nthresh");
const orderPill  = $("order");
const nviewEl     = $("nview");
const nlegendEl  = $("nlegend");
const errorP     = $("error");
const nrunCount  = $("nrun-count");
const nrunBase   = $("nrun-base");

// ---- state ---------------------------------------------------------------
let runs = [];          // [{ label, files: { name: text } }] in load order
let full = null;        // cached ALL-functions matrix from one parse of the runs
let matrix = null;      // `full` sliced to the displayed function count
let view = "heat";      // 'heat' | 'trend' | 'diverge'
let valMode = "delta";  // 'delta' (Δ% vs p50) | 'abs' (CEst cycles)
let orderMode = "load"; // 'load' | 'cest'
let NTHRESH = 25;
let wasmReady = false;

// trends view: which function indices to plot (null = default top regressors,
// max 5). divergence view: the current run, the comparison reference, and how
// many functions to show. Reset when the run set changes (see analyze()).
let trendFns = null;
let curRun = null;      // divergence current run index (null -> latest)
let cmpRun = "base";    // divergence reference: 'base' (p50) or a run index
let dvgTopN = 10;       // divergence: 10 | 25 | 'all'
let lastPatternsKey = ""; // last applied patterns string, to know when to reset trend picks
const TREND_COLORS = ["#b42318", "#1f5fbf", "#b45309", "#6d28d9", "#0e7490"];

// ---- WASM load -----------------------------------------------------------
async function loadWasm() {
  const go = new Go(); // from ../v1/wasm_exec.js
  const resp = await fetch("../v1/cest-analyzer.wasm");
  const { instance } = await WebAssembly.instantiateStreaming(resp, go.importObject);
  go.run(instance); // registers globalThis.cestMatrix, then blocks on select{}
  wasmReady = true;
}
loadWasm().catch((e) => showError(`Failed to load WASM: ${e}`));

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

  const dirs = Array.from(groups.keys());
  const prefix = commonPrefixSegs(dirs); // trimmed from labels when many runs share it

  for (const dir of dirs) {
    const segs = dir.split("/");
    const trimmed = segs.slice(prefix.length).join("/");
    const label = uniqueLabel(trimmed || segs[segs.length - 1] || `run ${runs.length + 1}`);
    const filesObj = {};
    await Promise.all(groups.get(dir).map(async (f) => { filesObj[f.name] = await readFileText(f); }));
    runs.push({ label, files: filesObj });
  }
  hideError();
  await analyze();
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
// parseRuns runs the WASM core over every loaded run ONCE and caches the full
// function set (all functions, ordered by max CEst). This is the expensive step
// — it parses every run's callgrind file — so it runs only when the run set
// changes, never when the displayed function count changes. Returns true when a
// fresh full matrix is ready.
async function parseRuns() {
  if (!wasmReady) { showError("WASM still loading — try again in a moment."); return false; }
  if (runs.length === 0) { full = null; matrix = null; render(); return false; }

  const runsObj = {};
  runs.forEach((r) => { runsObj[r.label] = r.files; });

  const res = cestMatrix(runsObj, 0); // 0 => all functions; display count is sliced in JS
  if (res.error) { showError(res.error); return false; }

  const R = res.runs; // in load order; each run's cest holds every function
  const totals = R.map((r) => r.total);
  // p50 baseline: the median run by total CEst (lower-middle for even counts).
  const byTotal = totals.map((t, i) => [t, i]).sort((a, b) => a[0] - b[0]);
  const BASE = byTotal[Math.floor(R.length / 2)][1];
  const maxTotal = byTotal[byTotal.length - 1][0] || 1;

  full = { funcs: res.functions, R, totals, BASE, maxTotal };
  // The run set changed, so view selections keyed by run/function index reset.
  trendFns = null;
  curRun = R.length - 1;
  cmpRun = "base";
  if ($("formula") && res.formula) $("formula").textContent = res.formula;
  return true;
}

// applyTopN re-slices the cached full matrix to the displayed function count.
// Cheap (no parsing), so it runs on every functions-count change.
function applyTopN() {
  if (!full) return;
  const topN = Math.max(1, parseInt(topnInput.value, 10) || 25);
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
async function analyze() {
  if (await parseRuns()) applyTopN();
}

// ---- helpers (ported from the wireframe) ---------------------------------
const fmtM = (v) => (v / 1e6).toFixed(1) + "M";
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
  const b = matrix.R[matrix.BASE].cest[matrix.funcs[f]];
  const v = matrix.R[i].cest[matrix.funcs[f]];
  if (b === 0) return v > 0 ? Infinity : 0;
  return (v - b) / b * 100;
}
function cestOf(f, i) { return matrix.R[i].cest[matrix.funcs[f]]; }
// finiteDelta is deltaPct guarded for plotting: a function absent from the
// baseline has no defined %, so it sits on the baseline (0) rather than ∞.
function finiteDelta(f, i) { const d = deltaPct(f, i); return isFinite(d) ? d : 0; }
function totalDelta(i) { return (matrix.totals[i] - matrix.totals[matrix.BASE]) / matrix.totals[matrix.BASE] * 100; }
// self-share: a function's CEst as a percentage of its run's total CEst.
function selfShare(f, i) { const t = matrix.totals[i]; return t ? cestOf(f, i) / t * 100 : 0; }
// change vs p50 expressed as a percentage of THIS run's total CEst.
function deltaTotal(f, i) { const t = matrix.totals[i]; return t ? (cestOf(f, i) - cestOf(f, matrix.BASE)) / t * 100 : 0; }
function dColor(d) { return Math.abs(d) < 1 ? "#566173" : (d > 0 ? "#b42318" : "#1f7a55"); }
// shortLabel picks the run# segment for compact axis ticks ("4/accept/short_ci" -> "4").
function shortLabel(label) { return String(label).split("/")[0]; }
// labelLines stacks a path label one segment per line ("1/accept/short_ci" ->
// "1/" <br> "accept/" <br> "short_ci") so heatmap columns stay narrow.
function labelLines(label) {
  const parts = String(label).split("/");
  return parts.map((p, i) => esc(p) + (i < parts.length - 1 ? "/" : "")).join("<br>");
}
// diverging heat colour: green (improvement) ← neutral → red (regression)
function heatColor(d) {
  if (!isFinite(d)) return "#fbeceb";
  if (Math.abs(d) < 1) return "#f7f6ef";
  const mag = Math.min(Math.abs(d), 90) / 90;
  const L = 94 - mag * 42;
  return d > 0 ? "hsl(8 72% " + L + "%)" : "hsl(150 42% " + L + "%)";
}
function heatText(d) { return isFinite(d) && Math.abs(d) >= 48 ? "#fff" : "#0f172a"; }

// column order: load order, or by total CEst ascending
function colOrder() {
  const idx = matrix.R.map((_, i) => i);
  if (orderMode === "cest") {
    return idx.sort((a, b) => matrix.totals[a] - matrix.totals[b]);
  }
  return idx;
}

// ---- render --------------------------------------------------------------
function render() {
  renderChips();
  const n = runs.length;
  nrunCount.textContent = String(n);
  const infoCount = $("nrun-info-count");
  if (infoCount) infoCount.textContent = String(n);
  emptyHint.hidden = n > 0;
  clearBtn.hidden = n === 0;

  // Keep the view toggle visible even when empty so the layout reads as "results
  // go here"; the data-only controls hide via the controls-empty class.
  controlsEl.hidden = false;
  controlsEl.classList.toggle("controls-empty", n === 0);

  if (!matrix || n === 0) {
    nrunBase.textContent = "—";
    nviewEl.innerHTML = renderEmpty();
    nlegendEl.replaceChildren();
    return;
  }
  nrunBase.textContent = matrix.R[matrix.BASE].label;
  updateControls();
  const avail = nviewEl.clientWidth > 60 ? nviewEl.clientWidth : 1040;
  if (view === "trend") nviewEl.innerHTML = renderTrend(avail);
  else if (view === "diverge") nviewEl.innerHTML = renderDiverge();
  else nviewEl.innerHTML = renderHeat();
  nlegendEl.innerHTML = legendFor();
}

// updateControls hides the controls a view doesn't use: divergence has its own
// in-view current/reference/top-N selectors, so the Δ-mode toggle, ordering,
// and threshold pill don't apply there.
function updateControls() {
  const hide = view === "diverge";
  valseg.style.display = hide ? "none" : "";
  orderPill.style.display = hide ? "none" : "";
  const thPill = nthreshInp.closest(".pill");
  if (thPill) thPill.style.display = hide ? "none" : "";
}

function renderChips() {
  chipsEl.replaceChildren();
  runs.forEach((r, i) => {
    const isBase = matrix && i === matrix.BASE;
    const total = matrix ? matrix.totals[i] : 0;
    const pct = matrix ? Math.round(total / matrix.maxTotal * 100) : 0;

    const chip = document.createElement("div");
    chip.className = "rchip" + (isBase ? " base" : "");

    const lbl = document.createElement("div");
    lbl.className = "rlabel";
    lbl.textContent = r.label;
    lbl.title = r.label;

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
    rm.addEventListener("click", () => removeRun(i));

    chip.append(lbl, bar, rn, rm);
    chipsEl.appendChild(chip);
  });
}

// heatCellLabel is the text shown in a non-baseline heatmap cell, per value mode.
function heatCellLabel(f, i) {
  switch (valMode) {
    case "abs": return fmtM(cestOf(f, i));            // CEst cycles
    case "pct": return fmtShare(selfShare(f, i));     // CEst % of run total
    case "deltatotal": return fmtPct(deltaTotal(f, i)); // Δ% vs that run's total
    default: return fmtPct(deltaPct(f, i));           // Δ% vs p50
  }
}

function renderHeat() {
  const { funcs, R, BASE } = matrix;
  const cols = colOrder();
  let h = '<table class="heat"><thead><tr><th class="fn">function<div class="bv">baseline (p50)</div></th>';
  cols.forEach((i) => {
    const b = i === BASE ? " base-col" : "";
    h += '<th class="' + b + '">' + labelLines(R[i].label) + "</th>";
  });
  h += "</tr></thead><tbody>";
  funcs.forEach((fn, f) => {
    h += '<tr><td class="fn"><span class="fnname" title="' + esc(fn) + '">' + esc(fn) + '</span><div class="bv">' + fmtM(cestOf(f, BASE)) + "</div></td>";
    cols.forEach((i) => {
      if (i === BASE) {
        // The p50 column has no Δ; show the actual value for value modes, "base" for Δ modes.
        const baseCell = valMode === "abs" ? fmtM(cestOf(f, BASE))
          : valMode === "pct" ? fmtShare(selfShare(f, BASE)) : "base";
        h += '<td class="cell base-col" style="background:#e7f3ec;color:#1f7a55;">' + baseCell + "</td>";
        return;
      }
      const d = deltaPct(f, i);              // colour + flag always track Δ% vs p50
      const flagged = isFinite(d) && Math.abs(d) >= NTHRESH;
      h += '<td class="cell" style="background:' + heatColor(d) + ";color:" + heatText(d)
        + (flagged ? ";outline:1px solid var(--note);outline-offset:-1px" : "") + '">' + heatCellLabel(f, i) + "</td>";
    });
    h += "</tr>";
  });
  h += "</tbody></table>";
  return h;
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
    + "<span>Add runs to compute the median (p50) baseline and the per-function comparison across runs.</span></div></div>"
    + "</div>";
}
// Trends empty state: the plot-functions picker (ghost chips), a chart frame
// with the p50 baseline line, and the legend — mirroring the real view.
function emptyTrend() {
  const widths = [58, 46, 70, 38, 54, 64, 42, 60];
  const chips = widths.map((w) => '<span class="tfn dis"><span class="dot"></span><span class="sk-pill" style="width:' + w + 'px"></span></span>').join("");
  const pick = '<div class="trend-pick"><span class="lbl">plot functions</span>' + chips + '<span class="cnt">0 / 5 · total always shown</span></div>';
  const chart = '<div class="sk-chart">'
    + '<div class="sk-baseline"></div><span class="sk-baseline-lbl">baseline = p50 (0%)</span>'
    + '<div class="empty-msg"><div class="empty-card"><b>Trends chart appears here</b><span>Add runs to plot Δ% vs the p50 baseline across runs (load order).</span></div></div>'
    + "</div>";
  const leg = '<div class="trend-leg"><span style="color:#0f172a;font-weight:700;">— total CEst</span><span>Δ% vs p50 · load order</span></div>';
  return pick + chart + leg;
}
// Divergence empty state: the current/vs header (ghost selectors), the centered
// axis, and a hint.
function emptyDiverge() {
  const head = '<div class="dvg-head"><span class="dvg-h-lbl">current</span><span class="sk-pill sk-sel"></span>'
    + '<span class="dvg-h-lbl">vs</span><span class="sk-pill sk-sel"></span>'
    + '<span class="dvg-leg"><span class="sw up"></span>increased<span class="sw down"></span>decreased</span></div>';
  const body = '<div class="sk-chart" style="height:300px;"><div class="sk-vcenter"></div>'
    + '<div class="empty-msg"><div class="empty-card"><b>Divergence bars appear here</b><span>Add runs to compare each function’s self-share (pp) vs the p50 baseline.</span></div></div>'
    + "</div>";
  return head + body;
}

function legendFor() {
  if (view === "diverge") {
    return '<span>Each bar = a function’s change in <b>self-share</b> of total CEst, current run vs the '
      + 'chosen reference (<b>p50</b> by default, or any run) · '
      + '<span style="color:#b42318;font-weight:700;">red</span> gained share / '
      + '<span style="color:#1f7a55;font-weight:700;">green</span> lost share · sorted by current share. '
      + '<b>pp</b> = percentage points.</span>';
  }
  if (view === "trend") {
    return valMode === "abs"
      ? '<span>Total CEst cycles per run · ● p50 baseline · load order. Pick up to 5 functions to plot.</span>'
      : '<span>Δ% vs p50 (baseline = 0%). Watch where total rises above 0. Pick up to 5 functions to plot.</span>';
  }
  let cells;
  if (valMode === "abs") cells = "cells = <b>CEst cycles</b> (self, M = million)";
  else if (valMode === "pct") cells = "cells = <b>CEst %</b> — function’s share of its run’s total CEst";
  else if (valMode === "deltatotal") cells = "cells = <b>Δ % vs total</b> — (run − p50) ÷ that run’s total CEst";
  else cells = "cells = <b>Δ % vs p50</b>";
  return "<span>" + cells + " · colour = Δ% vs p50</span>"
    + '<span><span class="swatch" style="background:hsl(8 72% 70%)"></span>regression</span>'
    + '<span><span class="swatch" style="background:hsl(150 42% 70%)"></span>improvement</span>'
    + '<span><span class="swatch" style="background:#e7f3ec"></span>baseline (p50)</span>'
    + "<span>· outlined ≥ " + NTHRESH + "%</span>";
}

// ---- trends view ---------------------------------------------------------
// Line chart over the runs in load order. delta mode: Δ% vs p50 (baseline 0).
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
    refVal = totals[BASE]; refLabel = "p50 total (" + fmtM(totals[BASE]) + ")"; yfmt = fmtM;
    modeLabel = "absolute CEst cycles";
  } else if (valMode === "pct") {
    valueFn = (f, i) => selfShare(f, i);
    hasTotal = false; // total self-share is always 100%
    yfmt = (v) => v.toFixed(1) + "%";
    modeLabel = "CEst % of run total";
  } else if (valMode === "deltatotal") {
    valueFn = (f, i) => deltaTotal(f, i);
    totalArr = R.map((_, i) => totals[i] ? (totals[i] - totals[BASE]) / totals[i] * 100 : 0);
    refVal = 0; refLabel = "baseline = p50 (0%)"; yfmt = (v) => v.toFixed(2) + "%";
    modeLabel = "Δ% vs that run's total";
  } else {
    valueFn = (f, i) => finiteDelta(f, i);
    totalArr = R.map((_, i) => totalDelta(i));
    refVal = 0; refLabel = "baseline = p50 (0%)"; yfmt = (v) => Math.round(v) + "%";
    modeLabel = "Δ% vs p50";
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
  return pick + s + leg;
}

// ---- divergence view -----------------------------------------------------
// Diverging bar chart: each function's change in self-share of total CEst (pp),
// the current run vs a reference run (the p50 baseline by default, or any run).
// Red = gained share, green = lost share.
function renderDiverge() {
  const { funcs, R, totals, BASE } = matrix;
  const N = R.length;
  const cur = curRun == null ? N - 1 : Math.min(curRun, N - 1);
  const ref = cmpRun === "base" ? BASE : Math.min(parseInt(cmpRun, 10), N - 1);
  const refIsP50 = ref === BASE;
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

  let sel = '<select data-currun class="dvg-sel">';
  R.forEach((r, i) => { sel += '<option value="' + i + '"' + (i === cur ? " selected" : "") + ">" + esc(r.label) + "</option>"; });
  sel += "</select>";
  let csel = '<select data-cmprun class="dvg-sel"><option value="base"' + (cmpRun === "base" ? " selected" : "") + ">p50 baseline (auto)</option>";
  R.forEach((r, i) => { csel += '<option value="' + i + '"' + (cmpRun !== "base" && ref === i ? " selected" : "") + ">" + esc(r.label) + "</option>"; });
  csel += "</select>";
  const refTag = refIsP50
    ? '<span class="dvg-ref"><span class="dvg-dot"></span><span class="dvg-p50">p50 baseline</span><span class="dvg-rid">' + esc(R[BASE].label) + "</span></span>"
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

  const refLabel = refIsP50 ? "p50 baseline" : ("run " + esc(R[ref].label));
  const countLabel = (dvgTopN === "all" || shown.length >= funcs.length)
    ? ("all " + funcs.length + " functions")
    : ("top " + shown.length + " of " + funcs.length + " functions, by current share");
  return head + axis + '<div class="dvg-rows">' + rowsH + "</div>"
    + '<div class="dvg-foot">Δ self-share in percentage points (pp) · current run vs ' + refLabel + " · " + countLabel + "</div>";
}

// ---- mutations -----------------------------------------------------------
function removeRun(i) {
  runs.splice(i, 1);
  analyze();
}
function clearRuns() {
  runs = [];
  full = null;
  matrix = null;
  hideError();
  render();
}

// ---- events --------------------------------------------------------------
// Source choice: local files (default) or the hosted prof-results store. The
// store path opens the selection modal; its data wiring is the source-selection
// work, so for now the modal shows the table shell + empty state.
let source = "local";
const srcseg = $("srcseg");
const repoModal = $("repo-modal");
srcseg.addEventListener("click", (e) => {
  const b = e.target.closest("button[data-src]");
  if (!b) return;
  source = b.dataset.src;
  srcseg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
});

function openRepoModal() { repoModal.classList.add("on"); }
function closeRepoModal() { repoModal.classList.remove("on"); }
$("repo-cancel").addEventListener("click", closeRepoModal);
repoModal.addEventListener("click", (e) => { if (e.target === repoModal) closeRepoModal(); });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && repoModal.classList.contains("on")) closeRepoModal();
});

addRunsBtn.addEventListener("click", () => {
  if (source === "repo") openRepoModal();
  else dirInput.click();
});
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
patternsInput.addEventListener("input", scheduleApply);
patternsInput.addEventListener("keydown", (e) => { if (e.key === "Enter") commitApply(); });
nthreshInp.addEventListener("input", () => {
  NTHRESH = Math.max(0, parseInt(nthreshInp.value, 10) || 0);
  if (matrix) render();
});
orderPill.addEventListener("click", () => {
  orderMode = orderMode === "load" ? "cest" : "load";
  orderPill.textContent = "order: " + (orderMode === "load" ? "load" : "CEst") + " ▾";
  if (matrix) render();
});

// The divergence selectors and the trends function picker live inside the
// re-rendered view, so listen via delegation on the view container.
nviewEl.addEventListener("change", (e) => {
  const cc = e.target.closest("[data-currun]");
  if (cc) { curRun = parseInt(cc.value, 10); render(); return; }
  const cr = e.target.closest("[data-cmprun]");
  if (cr) { cmpRun = cr.value === "base" ? "base" : parseInt(cr.value, 10); render(); return; }
  const cn = e.target.closest("[data-dvgn]");
  if (cn) { dvgTopN = cn.value === "all" ? "all" : parseInt(cn.value, 10); render(); return; }
});
nviewEl.addEventListener("click", (e) => {
  const tf = e.target.closest("[data-trendfn]");
  if (!tf || tf.classList.contains("dis")) return;
  const f = parseInt(tf.getAttribute("data-trendfn"), 10);
  if (trendFns === null) trendFns = [];
  const idx = trendFns.indexOf(f);
  if (idx >= 0) trendFns.splice(idx, 1);
  else if (trendFns.length < 5) trendFns.push(f);
  render();
});

// The trends SVG is sized to the view width; re-render (debounced) on resize.
let resizeTimer = null;
window.addEventListener("resize", () => {
  if (!matrix || view !== "trend") return;
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(render, 120);
});

// ---- misc ----------------------------------------------------------------
function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
// ---- download -----------------------------------------------------------
// Same Blob + anchor mechanism as v1. Exports the complete comparison dataset
// (all functions, every run's CEst, totals, the p50 baseline) — not just the
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
  const topN = Math.max(1, parseInt(topnInput.value, 10) || 25);
  const runsObj = {};
  runs.forEach((r) => { runsObj[r.label] = r.files; });
  const pats = patternsInput.value.trim().split(/\s+/).filter(Boolean);
  const res = cestReport(runsObj, topN, pats); // rich report schema (all 9 counters)
  if (res.error) { showError(res.error); return; }
  download(res.json, "application/json", "cest-compare.json");
}
$("download-json").addEventListener("click", downloadJson);

function showError(msg) { errorP.textContent = msg; errorP.hidden = false; }
function hideError() { errorP.hidden = true; errorP.textContent = ""; }

// Paint the initial empty state (view toggle + results placeholder) on load.
render();
