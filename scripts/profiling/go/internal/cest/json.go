package cest

import (
	"encoding/json"
	"io"
)

// ---------------------------------------------------------------------------
// JSON report schema
// ---------------------------------------------------------------------------
// A run carries the total CEst, a flat top-N functions list, and the
// per-pattern and per-category subtotals. The web UI parses this directly.

// Metric is one counter value with its per-metric run-total share (0-100).
type Metric struct {
	Number  int64   `json:"number"`
	Percent float64 `json:"percent"`
}

// StatRow is a named row carrying CEst and all 9 components. Key order follows
// the agreed schema: CEst first, then the counters.
type StatRow struct {
	Name string `json:"name,omitempty"` // omitted on the run total
	CEst Metric `json:"CEst"`
	Ir   Metric `json:"Ir"`
	Bim  Metric `json:"Bim"`
	Bcm  Metric `json:"Bcm"`
	I1mr Metric `json:"I1mr"`
	D1mr Metric `json:"D1mr"`
	D1mw Metric `json:"D1mw"`
	ILmr Metric `json:"ILmr"`
	DLmr Metric `json:"DLmr"`
	DLmw Metric `json:"DLmw"`
}

// TotalJSON is the run total. CEst only, by design; per-component totals are
// the denominators behind every Metric.Percent and are recoverable from the
// component breakdown if needed.
type TotalJSON struct {
	CEst Metric `json:"CEst"`
}

// RunJSON is one analyzed run.
type RunJSON struct {
	Label      string    `json:"label"`
	MainFile   string    `json:"mainFile"`
	Total      TotalJSON `json:"total"`
	Functions  []StatRow `json:"functions"`  // flat top-N by CEst
	Patterns   []StatRow `json:"patterns"`   // per-pattern subtotals
	Categories []StatRow `json:"categories"` // per-category subtotals
}

// ReportJSON is the top-level document. Multiple runs compare against runs[0].
type ReportJSON struct {
	Formula  string    `json:"formula"`
	TopN     int       `json:"topN"`
	Patterns []string  `json:"patterns"` // requested filter patterns, echoed
	Runs     []RunJSON `json:"runs"`
}

// Formula is the CEst equation, echoed into the JSON report for reference.
const Formula = "CEst = Ir + 10*(I1mr+D1mr+D1mw) + 100*(ILmr+DLmr+DLmw) + 10*(Bcm+Bim)"

// statRow builds a StatRow for e, with each metric's percent taken against the
// matching field of total (the run's grand-total Events).
func statRow(name string, e, total Events) StatRow {
	return StatRow{
		Name: name,
		CEst: Metric{e.CEst(), Pct(e.CEst(), total.CEst())},
		Ir:   Metric{e.Ir, Pct(e.Ir, total.Ir)},
		Bim:  Metric{e.Bim, Pct(e.Bim, total.Bim)},
		Bcm:  Metric{e.Bcm, Pct(e.Bcm, total.Bcm)},
		I1mr: Metric{e.I1mr, Pct(e.I1mr, total.I1mr)},
		D1mr: Metric{e.D1mr, Pct(e.D1mr, total.D1mr)},
		D1mw: Metric{e.D1mw, Pct(e.D1mw, total.D1mw)},
		ILmr: Metric{e.ILmr, Pct(e.ILmr, total.ILmr)},
		DLmr: Metric{e.DLmr, Pct(e.DLmr, total.DLmr)},
		DLmw: Metric{e.DLmw, Pct(e.DLmw, total.DLmw)},
	}
}

// BuildReportJSON assembles the JSON document from one or more analyzed runs.
func BuildReportJSON(dirs []*DirResult, patterns []string, cats []Category, topn int) ReportJSON {
	rep := ReportJSON{
		Formula:  Formula,
		TopN:     topn,
		Patterns: patterns,
		Runs:     make([]RunJSON, 0, len(dirs)),
	}
	for _, dr := range dirs {
		total := dr.Res.Total
		run := RunJSON{
			Label:    dr.Label,
			MainFile: dr.Main,
			Total:    TotalJSON{CEst: Metric{total.CEst(), 100}},
		}
		for _, fn := range TopNFnsAny(dr.Res.FnSelf, patterns, topn) {
			run.Functions = append(run.Functions, statRow(fn.Name, fn.Events, total))
		}
		for i, pat := range patterns {
			run.Patterns = append(run.Patterns, statRow(pat, dr.Res.PatSums[i], total))
		}
		for i, cat := range cats {
			run.Categories = append(run.Categories, statRow(cat.Label, dr.Res.CatSums[i], total))
		}
		rep.Runs = append(rep.Runs, run)
	}
	return rep
}

// WriteJSON encodes the indented JSON report to w. Taking an io.Writer (like
// WriteReport and WriteMarkdown) lets the CLI write to a file and the WASM
// bridge write to a strings.Builder with the same function.
func WriteJSON(w io.Writer, dirs []*DirResult, patterns []string, cats []Category, topn int) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(BuildReportJSON(dirs, patterns, cats, topn))
}
