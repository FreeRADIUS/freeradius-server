// app.js wires the page to the Go WASM bridge exported as globalThis.analyzeCest.
//
// Flow: load cest-analyzer.wasm -> read selected files as text with FileReader
// -> call analyzeCest(runs, patterns, topN) -> render { text, markdown }.

const $ = (id) => document.getElementById(id);

const runBtn = $("run");
const addRunBtn = $("add-run");
const runsContainer = $("runs");
const runRowTemplate = $("run-row");
const patternsInput = $("patterns");
const topnInput = $("topn");
const outputSection = $("output");
const reportPre = $("report");
const downloadBtn = $("download");
const errorP = $("error");

let lastMarkdown = ""; // populated after each successful run

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

    reportPre.textContent = result.text;
    lastMarkdown = result.markdown;
    outputSection.hidden = false;
  } catch (e) {
    showError(String(e));
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = "Analyze";
  }
}

runBtn.addEventListener("click", run);
addRunBtn.addEventListener("click", () => addRunRow());

// --- Markdown download -----------------------------------------------------

downloadBtn.addEventListener("click", () => {
  if (!lastMarkdown) return;
  const blob = new Blob([lastMarkdown], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "cest-report.md";
  a.click();
  URL.revokeObjectURL(url);
});

// --- Error helpers ---------------------------------------------------------

function showError(msg) {
  errorP.textContent = msg;
  errorP.hidden = false;
}

function hideError() {
  errorP.hidden = true;
  errorP.textContent = "";
}
