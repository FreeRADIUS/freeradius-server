package cest

import (
	"math"
	"testing"
)

// mkRun builds a DirResult whose functions have the given CEst values. Setting
// only Ir makes CEst == Ir (CEst = Ir + 10*… with the rest zero), so the test
// can pin exact CEst values per function.
func mkRun(label string, fns map[string]int64) *DirResult {
	fnSelf := make(map[string]Events, len(fns))
	var total Events
	for n, c := range fns {
		e := Events{Ir: c}
		fnSelf[n] = e
		total = total.Add(e)
	}
	return &DirResult{Label: label, Main: "callgrind.out.1", Res: &Result{Total: total, FnSelf: fnSelf}}
}

// TestCompare checks the lowest-CEst baseline, Δ% vs best, spread, and the
// spread-descending / "new"-last ordering — the same math the v2 UI compare
// view computes in JS.
func TestCompare(t *testing.T) {
	runs := []*DirResult{
		mkRun("A", map[string]int64{"f1": 12_400_000, "f2": 8_200_000, "f3": 3_000_000}),
		mkRun("B", map[string]int64{"f1": 13_100_000, "f2": 8_200_000, "f3": 5_000_000}),
		mkRun("C", map[string]int64{"f1": 11_900_000, "f2": 9_000_000}), // f3 absent (CEst 0)
	}
	rows := Compare(runs)

	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	// Sorted by spread descending, with the infinite-spread ("new") row last.
	if rows[0].Name != "f1" || rows[1].Name != "f2" || rows[2].Name != "f3" {
		t.Fatalf("order = %s, %s, %s; want f1, f2, f3", rows[0].Name, rows[1].Name, rows[2].Name)
	}

	// f1: lowest CEst is run C (index 2) -> baseline.
	if rows[0].Best != 2 {
		t.Errorf("f1 best = %d; want 2 (run C)", rows[0].Best)
	}
	if got := rows[0].SpreadPct; math.Abs(got-10.0840) > 0.01 { // (13.1-11.9)/11.9
		t.Errorf("f1 spread = %.4f; want ~10.0840", got)
	}
	if got := rows[0].DeltaPct[0]; math.Abs(got-4.2017) > 0.01 { // run A vs best (0.5/11.9)
		t.Errorf("f1 run A Δ = %.4f; want ~4.2017", got)
	}
	if rows[0].DeltaPct[2] != 0 {
		t.Errorf("f1 best-run Δ = %v; want 0", rows[0].DeltaPct[2])
	}

	// f2: runs A and B tie at the lowest; the first (A, index 0) is the baseline.
	if rows[1].Best != 0 {
		t.Errorf("f2 best = %d; want 0 (run A)", rows[1].Best)
	}
	if got := rows[1].SpreadPct; math.Abs(got-9.7561) > 0.01 { // (9.0-8.2)/8.2
		t.Errorf("f2 spread = %.4f; want ~9.7561", got)
	}

	// f3: absent from run C, so the baseline is that 0-CEst run, spread is "new"
	// (infinite), and the runs that have it show an infinite Δ.
	if !math.IsInf(rows[2].SpreadPct, 1) {
		t.Errorf("f3 spread = %v; want +Inf (new)", rows[2].SpreadPct)
	}
	if rows[2].Best != 2 {
		t.Errorf("f3 best = %d; want 2 (run C, CEst 0)", rows[2].Best)
	}
	if !math.IsInf(rows[2].DeltaPct[1], 1) {
		t.Errorf("f3 run B Δ = %v; want +Inf", rows[2].DeltaPct[1])
	}
}

// TestFilterRows checks that pattern scoping keeps only matching functions
// (substring, case-insensitive, any-of) without altering their per-row values.
func TestFilterRows(t *testing.T) {
	rows := []CompareRow{
		{Name: "_talloc_free", SpreadPct: 10},
		{Name: "fr_rb_find", SpreadPct: 5},
		{Name: "TALLOC_pool", SpreadPct: 1},
	}
	got := filterRows(rows, []string{"talloc"})
	if len(got) != 2 {
		t.Fatalf("got %d rows for 'talloc'; want 2 (_talloc_free, TALLOC_pool)", len(got))
	}
	for _, r := range got {
		if r.Name != "_talloc_free" && r.Name != "TALLOC_pool" {
			t.Errorf("unexpected row %q", r.Name)
		}
	}
	if n := len(filterRows(rows, nil)); n != 3 {
		t.Errorf("empty patterns kept %d rows; want all 3", n)
	}
}
