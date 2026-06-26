package cest

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Per-function CEst comparison across runs
// ---------------------------------------------------------------------------
// The terminal/WASI equivalent of the v2 UI compare view: for the union of all
// functions, each run's self-CEst side by side, with diffs measured against the
// function's lowest-CEst ("best") run, plus a spread (worst / best - 1). This is
// a presentation over the same Analyze output the UI uses (DirResult.Res.FnSelf),
// so the CLI and the browser report identical numbers.

// CompareRow is one function's CEst across the compared runs.
type CompareRow struct {
	Name      string    // function name
	CEst      []int64   // CEst per run, aligned to the results slice (0 if absent)
	DeltaPct  []float64 // Δ% vs the row's lowest CEst; 0 for the best run; +Inf when best is 0 and this run > 0
	Best      int       // index of the lowest-CEst (baseline) run
	SpreadPct float64   // (max-min)/min*100; +Inf when a run lacks the function (min == 0 < max)
}

// RunCEst is the minimal per-run input to CompareCEst: a label and each
// function's self-CEst. The browser already has this (parsed once per run via
// the cestRunCEst bridge), so the compare view can reuse this math without
// re-parsing files — the same code path the CLI uses through Compare.
type RunCEst struct {
	Label string
	Total int64
	CEst  map[string]int64 // function name -> self CEst
}

// Compare is the CLI/DirResult entry point: it projects each run to its
// per-function CEst and delegates to CompareCEst.
func Compare(results []*DirResult) []CompareRow {
	runs := make([]RunCEst, len(results))
	for i, dr := range results {
		cm := make(map[string]int64, len(dr.Res.FnSelf))
		for n, ev := range dr.Res.FnSelf {
			cm[n] = ev.CEst()
		}
		runs[i] = RunCEst{Label: dr.Label, Total: dr.Res.Total.CEst(), CEst: cm}
	}
	return CompareCEst(runs)
}

// CompareCEst builds the per-function CEst comparison across runs: the union of
// every function, each with per-run CEst, Δ% vs that function's lowest-CEst run,
// and the spread. Rows are sorted by spread descending, with functions absent
// from a run (infinite spread, "new") last. This is the single implementation of
// the compare math, shared by the CLI (via Compare) and the browser (via the
// cestCompare WASM bridge). Row CEst/DeltaPct are aligned to the runs slice.
func CompareCEst(runs []RunCEst) []CompareRow {
	names := map[string]struct{}{}
	for _, r := range runs {
		for n := range r.CEst {
			names[n] = struct{}{}
		}
	}

	rows := make([]CompareRow, 0, len(names))
	for name := range names {
		cests := make([]int64, len(runs))
		min, max := int64(math.MaxInt64), int64(0)
		for i, r := range runs {
			c := r.CEst[name] // 0 when absent
			cests[i] = c
			if c < min {
				min = c
			}
			if c > max {
				max = c
			}
		}
		best := 0
		for i, c := range cests {
			if c == min {
				best = i
				break
			}
		}
		deltas := make([]float64, len(runs))
		for i, c := range cests {
			switch {
			case i == best:
				deltas[i] = 0
			case min > 0:
				deltas[i] = float64(c-min) / float64(min) * 100
			default: // min == 0, this run > 0
				deltas[i] = math.Inf(1)
			}
		}
		spread := math.Inf(1)
		if min > 0 {
			spread = float64(max-min) / float64(min) * 100
		} else if max == 0 {
			spread = 0 // every run is 0 for this function
		}
		rows = append(rows, CompareRow{Name: name, CEst: cests, DeltaPct: deltas, Best: best, SpreadPct: spread})
	}

	sort.Slice(rows, func(i, j int) bool {
		si, sj := rows[i].SpreadPct, rows[j].SpreadPct
		ii, ij := math.IsInf(si, 1), math.IsInf(sj, 1)
		if ii != ij {
			return ij // a finite spread sorts before an infinite ("new") one
		}
		if !ii && si != sj {
			return si > sj // spread descending
		}
		return rows[i].Name < rows[j].Name // stable tiebreak (and orders the "new" tail)
	})
	return rows
}

// fmtMillions formats a CEst count as millions, mirroring the v2 UI compare
// table's fmtM3: 3 decimals normally, but when a nonzero value would round to
// 0.000M it shows enough extra decimals to keep ~3 significant figures (capped
// at 12), so small per-function CEsts stay legible instead of collapsing to
// 0.000M. A genuine zero (function absent in a run) still prints 0.000M.
func fmtMillions(c int64) string {
	m := float64(c) / 1e6
	abs := math.Abs(m)
	dec := 3
	if abs > 0 && abs < 0.0005 { // below where %.3f rounds to 0.000
		dec = 2 - int(math.Floor(math.Log10(abs)))
		if dec > 12 {
			dec = 12
		}
	}
	return fmt.Sprintf("%.*fM", dec, m)
}

// compareCell is "<value>M <best|+Δ%|+inf>" for one run's cell, or "absent" when
// the function has no CEst in that run (CEst 0). An absent run is necessarily the
// lowest, so the present runs read as "+inf" against it.
func compareCell(r CompareRow, i int) string {
	if r.CEst[i] == 0 {
		return "absent"
	}
	v := fmtMillions(r.CEst[i])
	switch {
	case i == r.Best:
		return v + " best"
	case math.IsInf(r.DeltaPct[i], 1):
		return v + " +inf"
	default:
		return v + fmt.Sprintf(" +%.1f%%", r.DeltaPct[i])
	}
}

func spreadCell(s float64) string {
	switch {
	case math.IsInf(s, 1):
		return "new"
	case s < 0.05:
		return "0%"
	default:
		return fmt.Sprintf("+%.1f%%", s)
	}
}

// matchAny reports whether name contains any of the (lowercased) patterns; an
// empty list matches everything. Substring / case-insensitive, like the UI's
// patterns field.
func matchAny(name string, lpats []string) bool {
	if len(lpats) == 0 {
		return true
	}
	ln := strings.ToLower(name)
	for _, p := range lpats {
		if strings.Contains(ln, p) {
			return true
		}
	}
	return false
}

// filterRows keeps the compare rows whose function name matches any pattern
// (empty patterns => all rows). Per-function baseline/spread are independent of
// the row set, so filtering after Compare equals scoping the compare to those
// patterns — the same result the UI gives when its patterns field is set.
func filterRows(rows []CompareRow, patterns []string) []CompareRow {
	if len(patterns) == 0 {
		return rows
	}
	lpats := make([]string, len(patterns))
	for i, p := range patterns {
		lpats[i] = strings.ToLower(p)
	}
	out := make([]CompareRow, 0, len(rows))
	for _, r := range rows {
		if matchAny(r.Name, lpats) {
			out = append(out, r)
		}
	}
	return out
}

// WriteCompare renders the per-function CEst comparison table for two or more
// runs: each function's CEst per run, the diff vs its lowest-CEst run, and the
// spread, sorted by spread descending with absent-in-a-run functions ("new")
// last. Runs are referenced as run0, run1, ... with a legend mapping each to its
// directory. Optional patterns scope the rows to functions whose name contains
// any of them (substring, case-insensitive), like the UI's patterns field.
func WriteCompare(w io.Writer, results []*DirResult, patterns []string) {
	rows := filterRows(Compare(results), patterns)
	fmt.Fprintln(w, "===================================================")
	fmt.Fprintln(w, "COMPARE  (per-function CEst; diffs vs each function's lowest-CEst run)")
	fmt.Fprintln(w, "===================================================")
	for i, dr := range results {
		fmt.Fprintf(w, "[run %d] %s  (main %s, total CEst %d)\n", i, dr.Label, dr.Main, dr.Res.Total.CEst())
	}
	if len(patterns) > 0 {
		fmt.Fprintf(w, "filter: functions matching '%s'\n", strings.Join(patterns, "' '"))
	}
	fmt.Fprintln(w)

	const nameW = 40
	fmt.Fprintf(w, "%-*s", nameW, "Function")
	for i := range results {
		fmt.Fprintf(w, " %22s", fmt.Sprintf("run%d CEst", i))
	}
	fmt.Fprintf(w, " %12s\n", "spread")
	for _, r := range rows {
		fmt.Fprintf(w, "%-*s", nameW, r.Name)
		for i := range results {
			fmt.Fprintf(w, " %22s", compareCell(r, i))
		}
		fmt.Fprintf(w, " %12s\n", spreadCell(r.SpreadPct))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "best   = the run with the lowest CEst for that function (the baseline)")
	fmt.Fprintln(w, "absent = the function has no CEst in that run; it then becomes the baseline, so present runs read '+inf'")
	fmt.Fprintln(w, "+Δ%    = that run's CEst above best; spread = worst / best - 1; 'new' = a run lacks the function")
}

// ---- JSON (mirrors the v2 UI compare "Download JSON") ---------------------

type compareRunJSON struct {
	Label     string `json:"label"`
	Main      string `json:"main"`
	TotalCEst int64  `json:"totalCEst"`
}

type compareFnJSON struct {
	Name           string              `json:"name"`
	CEst           map[string]int64    `json:"cest"`           // keyed by run label
	DeltaPctVsBest map[string]*float64 `json:"deltaPctVsBest"` // null where a run lacks the function (infinite)
	Best           string              `json:"best"`           // label of the lowest-CEst run
	SpreadPct      *float64            `json:"spreadPct"`      // null = a run lacks the function ("new")
}

type compareJSON struct {
	Schema    string           `json:"schema"`
	Baseline  string           `json:"baseline"`
	Runs      []compareRunJSON `json:"runs"`
	Functions []compareFnJSON  `json:"functions"`
}

// finiteOrNil returns a pointer to f, or nil when f is +Inf, since JSON has no
// infinity; the UI's compare export uses null for the same case.
func finiteOrNil(f float64) *float64 {
	if math.IsInf(f, 1) {
		return nil
	}
	return &f
}

// WriteCompareJSON encodes the per-function CEst comparison as JSON, matching
// the UI compare "Download JSON" shape (cest-compare-1). Optional patterns scope
// the functions, like WriteCompare.
func WriteCompareJSON(w io.Writer, results []*DirResult, patterns []string) error {
	rows := filterRows(Compare(results), patterns)
	doc := compareJSON{Schema: "cest-compare-1", Baseline: "per-function lowest-CEst run"}
	for _, dr := range results {
		doc.Runs = append(doc.Runs, compareRunJSON{Label: dr.Label, Main: dr.Main, TotalCEst: dr.Res.Total.CEst()})
	}
	for _, r := range rows {
		fn := compareFnJSON{
			Name:           r.Name,
			CEst:           make(map[string]int64, len(results)),
			DeltaPctVsBest: make(map[string]*float64, len(results)),
			Best:           results[r.Best].Label,
			SpreadPct:      finiteOrNil(r.SpreadPct),
		}
		for i, dr := range results {
			fn.CEst[dr.Label] = r.CEst[i]
			fn.DeltaPctVsBest[dr.Label] = finiteOrNil(r.DeltaPct[i])
		}
		doc.Functions = append(doc.Functions, fn)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
