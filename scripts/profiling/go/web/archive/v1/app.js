// app.js wires the page to the Go WASM bridge exported as globalThis.analyzeCest.
//
// Flow: load cest-analyzer.wasm -> read selected files as text with FileReader
// -> call analyzeCest(runs, patterns, topN) -> render the Tables view from
// { json }, and keep { json } for the Download JSON button.

const $ = (id) => document.getElementById(id);

const runBtn = $("run");
const addRunBtn = $("add-run");
const runsContainer = $("runs");
const runRowTemplate = $("run-row");
const patternsInput = $("patterns");
const topnInput = $("topn");
const outputSection = $("output");
const downloadJsonBtn = $("download-json");
const errorP = $("error");
const metricSelect = $("metric");
const tablesContainer = $("tables");
const tablesHint = $("tables-hint");

let lastJsonText = ""; // raw JSON string, for the Download JSON button
let lastReport = null; // parsed JSON report object, drives the Tables view

// Component column order for the "All components" table (logical grouping;
// the JSON object key order is not significant for display).
const ALL_METRICS = ["CEst", "Ir", "I1mr", "D1mr", "D1mw", "ILmr", "DLmr", "DLmw", "Bcm", "Bim"];

// --- Dynamic run rows ------------------------------------------------------
// Each row is one labelled run (one profiling directory's files). The first
// row is created on load; "Add run" appends more so the WASM core can compare
// 2+ runs. The remove button is hidden while only one row remains.

function addRunRow() {
  const row = runRowTemplate.content.firstElementChild.cloneNode(true);
  row.querySelector(".remove-run").addEventListener("click", () => {
    row.remove();
    refreshRemoveButtons();
  });
  runsContainer.appendChild(row);
  refreshRemoveButtons();
  return row;
}

// Hide the remove button when a single run is left (a run is mandatory).
function refreshRemoveButtons() {
  const rows = runsContainer.querySelectorAll(".run-row");
  rows.forEach((row) => {
    row.querySelector(".remove-run").hidden = rows.length <= 1;
  });
}

addRunRow(); // start with one run

// --- Load the WASM module --------------------------------------------------

async function loadWasm() {
  const go = new Go(); // provided by wasm_exec.js
  const resp = await fetch("cest-analyzer.wasm");
  const { instance } = await WebAssembly.instantiateStreaming(resp, go.importObject);
  go.run(instance); // registers globalThis.analyzeCest, then blocks on select{}
  runBtn.disabled = false;
  runBtn.textContent = "Analyze";
}

loadWasm().catch((e) => showError(`Failed to load WASM: ${e}`));

// --- Read a File as text ---------------------------------------------------

function readFileText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}

// --- Run ------------------------------------------------------------------

// collectRuns reads every non-empty run row into the { label: {file: text} }
// shape analyzeCest expects. Insertion order is preserved, so the first row is
// the comparison baseline. Labels are defaulted ("run 1", ...) when blank and
// made unique by suffixing, since the WASM side keys runs by label.
async function collectRuns() {
  const rows = Array.from(runsContainer.querySelectorAll(".run-row"));
  const runs = {};
  const usedLabels = new Set();

  for (let i = 0; i < rows.length; i++) {
    const files = Array.from(rows[i].querySelector(".run-files-input").files || []);
    if (files.length === 0) continue; // skip empty rows

    let label = rows[i].querySelector(".run-label-input").value.trim() || `run ${i + 1}`;
    let unique = label;
    for (let n = 2; usedLabels.has(unique); n++) unique = `${label} (${n})`;
    usedLabels.add(unique);

    const filesObj = {};
    await Promise.all(
      files.map(async (f) => {
        filesObj[f.name] = await readFileText(f);
      })
    );
    runs[unique] = filesObj;
  }
  return runs;
}

async function run() {
  hideError();

  const patterns = patternsInput.value.trim().split(/\s+/).filter(Boolean);
  if (patterns.length === 0) {
    showError("Enter at least one pattern.");
    return;
  }
  const topN = Math.max(1, parseInt(topnInput.value, 10) || 10);

  runBtn.disabled = true;
  runBtn.textContent = "Analyzing…";
  try {
    const runs = await collectRuns();
    if (Object.keys(runs).length === 0) {
      showError("Select one or more callgrind.out.* files in at least one run.");
      return;
    }

    const result = analyzeCest(runs, patterns, topN);
    if (result.error) {
      showError(result.error);
      return;
    }

    lastJsonText = result.json || "";
    lastReport = lastJsonText ? JSON.parse(lastJsonText) : null;
    renderTables();
    outputSection.hidden = false;
    updateScrollHints(); // measure now that the output section is visible
  } catch (e) {
    showError(String(e));
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = "Analyze";
  }
}

runBtn.addEventListener("click", run);
addRunBtn.addEventListener("click", () => addRunRow());

// --- Tables view -----------------------------------------------------------
// Driven by the parsed JSON report (lastReport) and the metric <select>.

const fmtNum = (n) => n.toLocaleString("en-US");
const fmtPct = (p) => `${p.toFixed(2)}%`;

// el builds a DOM element with optional text and children. Text is set via
// textContent so function names are never interpreted as HTML.
function el(tag, opts = {}, children = []) {
  const node = document.createElement(tag);
  if (opts.text != null) node.textContent = opts.text;
  if (opts.className) node.className = opts.className;
  children.forEach((c) => node.appendChild(c));
  return node;
}

function metricLabel() {
  return metricSelect.value === "all" ? "All Stats" : metricSelect.value;
}

// renderTables redraws the Tables view for the current metric selection.
function renderTables() {
  tablesContainer.replaceChildren();
  if (!lastReport || !lastReport.runs || lastReport.runs.length === 0) {
    tablesContainer.appendChild(el("p", { text: "No JSON report available." }));
    updateScrollHints();
    return;
  }
  const runs = lastReport.runs;
  const sections = [
    ["Functions (top by CEst)", "functions"],
    ["Patterns", "patterns"],
    ["Categories", "categories"],
  ];
  if (metricSelect.value === "all") {
    // One wide table per run per section: all components side by side.
    runs.forEach((run) => {
      tablesContainer.appendChild(el("h3", { text: runHeading(run) }));
      sections.forEach(([title, key]) => {
        tablesContainer.appendChild(el("h4", { text: title }));
        tablesContainer.appendChild(allComponentsTable(run[key] || []));
      });
    });
  } else {
    // One table per section, comparing the chosen metric across all runs.
    const metric = metricSelect.value;
    sections.forEach(([title, key]) => {
      tablesContainer.appendChild(el("h3", { text: title }));
      tablesContainer.appendChild(singleMetricTable(runs, key, metric));
    });
  }
  updateScrollHints();
}

// runHeading labels a run by its display label and chosen main file.
function runHeading(run) {
  return `${run.label}  (${run.mainFile})`;
}

// allComponentsTable: rows = entries, columns = name + each component number.
function allComponentsTable(rows) {
  const head = el("tr", {}, [el("th", { text: "Name" }), ...ALL_METRICS.map((m) => el("th", { text: m, className: "num" }))]);
  const body = rows.map((r) =>
    el("tr", {}, [
      el("td", { text: r.name || "total" }),
      ...ALL_METRICS.map((m) => el("td", { text: fmtNum(r[m].number), className: "num" })),
    ])
  );
  return table(head, body);
}

// singleMetricTable: rows = union of entry names across runs, columns = name +
// (number, %) per run. Rows are ordered by the first run's appearance, which
// (for functions) is already sorted by CEst descending.
function singleMetricTable(runs, key, metric) {
  const order = [];
  const seen = new Set();
  const byNamePerRun = runs.map((run) => {
    const map = new Map();
    (run[key] || []).forEach((r) => {
      const name = r.name || "total";
      map.set(name, r);
      if (!seen.has(name)) {
        seen.add(name);
        order.push(name);
      }
    });
    return map;
  });

  const head = el("tr", {}, [
    el("th", { text: "Name" }),
    ...runs.flatMap((run) => [
      el("th", { text: run.label, className: "num" }),
      el("th", { text: "%", className: "num" }),
    ]),
  ]);
  const body = order.map((name) =>
    el("tr", {}, [
      el("td", { text: name }),
      ...byNamePerRun.flatMap((map) => {
        const r = map.get(name);
        if (!r) return [el("td", { text: "-", className: "num" }), el("td", { text: "-", className: "num" })];
        return [
          el("td", { text: fmtNum(r[metric].number), className: "num" }),
          el("td", { text: fmtPct(r[metric].percent), className: "num" }),
        ];
      }),
    ])
  );
  if (body.length === 0) body.push(el("tr", {}, [el("td", { text: "(none)" })]));
  return table(head, body);
}

function table(headRow, bodyRows) {
  // Wrap the table so a wide one scrolls within its own box rather than
  // pushing the whole page sideways.
  return el("div", { className: "tables-scroll" }, [
    el("table", { className: "tables-data" }, [
      el("thead", {}, [headRow]),
      el("tbody", {}, bodyRows),
    ]),
  ]);
}

metricSelect.addEventListener("change", renderTables);

// --- Scroll hints ----------------------------------------------------------
// The hint is shown only when a table actually overflows horizontally.
// Overflow can only be measured on a visible element, so this is re-run after
// each render and on resize.

function overflowsX(node) {
  return node.scrollWidth > node.clientWidth + 1;
}

function updateScrollHints() {
  const tableScrolls = Array.from(tablesContainer.querySelectorAll(".tables-scroll"));
  tablesHint.hidden = !tableScrolls.some(overflowsX);
}

window.addEventListener("resize", updateScrollHints);

// --- Downloads -------------------------------------------------------------

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

downloadJsonBtn.addEventListener("click", () => download(lastJsonText, "application/json", "cest-report.json"));

// --- Error helpers ---------------------------------------------------------

function showError(msg) {
  errorP.textContent = msg;
  errorP.hidden = false;
}

function hideError() {
  errorP.hidden = true;
  errorP.textContent = "";
}
