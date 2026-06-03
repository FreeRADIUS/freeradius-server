// app.js wires the page to the Go WASM bridge exported as globalThis.analyzeCest.
//
// Flow: load cest-analyzer.wasm -> read selected files as text with FileReader
// -> call analyzeCest(runs, patterns, topN) -> render { text, markdown }.

const $ = (id) => document.getElementById(id);

const runBtn = $("run");
const filesInput = $("files");
const patternsInput = $("patterns");
const topnInput = $("topn");
const outputSection = $("output");
const reportPre = $("report");
const downloadBtn = $("download");
const errorP = $("error");

let lastMarkdown = ""; // populated after each successful run

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

async function run() {
  hideError();
  const files = Array.from(filesInput.files || []);
  if (files.length === 0) {
    showError("Select one or more callgrind.out.* files first.");
    return;
  }

  const patterns = patternsInput.value.trim().split(/\s+/).filter(Boolean);
  if (patterns.length === 0) {
    showError("Enter at least one pattern.");
    return;
  }
  const topN = Math.max(1, parseInt(topnInput.value, 10) || 10);

  runBtn.disabled = true;
  runBtn.textContent = "Analyzing…";
  try {
    // All selected files are treated as one run. To compare builds, this is
    // where you'd group files into multiple labelled runs.
    const filesObj = {};
    await Promise.all(
      files.map(async (f) => {
        filesObj[f.name] = await readFileText(f);
      })
    );
    const runs = { "uploaded run": filesObj };

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
