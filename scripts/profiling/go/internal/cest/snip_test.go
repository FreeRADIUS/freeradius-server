package cest

import "testing"

// ev makes an Events whose CEst equals c (only Ir set, so CEst = Ir).
func ev(c int64) Events { return Events{Ir: c} }

// chainEdges builds inclusive-cost edges for a straight call chain caller->callee.
// For a single chain, the inclusive cost of an edge is the sum of self-costs at
// and below the callee; the exact value doesn't matter for a single-caller chain
// (weight only matters when a callee has multiple callers), so we use the
// callee's self-cost as a stand-in.
func chainEdges(self map[string]Events, chain []string) map[string]map[string]Events {
	e := map[string]map[string]Events{}
	for i := 0; i+1 < len(chain); i++ {
		caller, callee := chain[i], chain[i+1]
		if e[caller] == nil {
			e[caller] = map[string]Events{}
		}
		e[caller][callee] = self[callee]
	}
	return e
}

// TestSnipChain covers the two worked examples from the spec on the chain
// app_handler -> talloc_pool -> _talloc -> memcpy -> __memmove_avx.
func TestSnipChain(t *testing.T) {
	self := map[string]Events{
		"app_handler":   ev(5),
		"talloc_pool":   ev(8),
		"_talloc":       ev(12),
		"memcpy":        ev(20),
		"__memmove_avx": ev(40),
	}
	edges := chainEdges(self, []string{"app_handler", "talloc_pool", "_talloc", "memcpy", "__memmove_avx"})

	// SnipSelf talloc,memcpy : talloc_pool/_talloc/memcpy fold into app_handler;
	// __memmove_avx is NOT matched, keeps its 40.
	got := SnipSelf(self, edges, []string{"talloc", "memcpy"})
	if c := got["app_handler"].CEst(); c != 45 { // 5 + 8 + 12 + 20
		t.Errorf("app_handler = %d; want 45", c)
	}
	if c := got["__memmove_avx"].CEst(); c != 40 {
		t.Errorf("__memmove_avx = %d; want 40 (unmatched, unchanged)", c)
	}
	if _, ok := got["memcpy"]; ok {
		t.Errorf("memcpy should be removed")
	}
	if total := totalCEst(got); total != 85 {
		t.Errorf("total = %d; want 85 (preserved)", total)
	}

	// SnipSelf talloc,memcpy,memmove : the whole library subtree collapses into app_handler.
	got2 := SnipSelf(self, edges, []string{"talloc", "memcpy", "memmove"})
	if c := got2["app_handler"].CEst(); c != 85 {
		t.Errorf("app_handler (all noise snipped) = %d; want 85", c)
	}
	if len(got2) != 1 {
		t.Errorf("want only app_handler left; got %d functions", len(got2))
	}
}

// TestSnipMultiCaller checks that a matched function called from two callers
// splits its self-cost by the per-edge inclusive weight.
func TestSnipMultiCaller(t *testing.T) {
	self := map[string]Events{"A": ev(10), "B": ev(30), "memcpy": ev(100)}
	// A and B both call memcpy; weight 1:3 by edge inclusive cost.
	edges := map[string]map[string]Events{
		"A": {"memcpy": ev(25)},
		"B": {"memcpy": ev(75)},
	}
	got := SnipSelf(self, edges, []string{"memcpy"})
	if c := got["A"].CEst(); c != 35 { // 10 + 100*(25/100)=25
		t.Errorf("A = %d; want 35", c)
	}
	if c := got["B"].CEst(); c != 105 { // 30 + 100*(75/100)=75
		t.Errorf("B = %d; want 105", c)
	}
	if totalCEst(got) != 140 {
		t.Errorf("total = %d; want 140", totalCEst(got))
	}
}

func totalCEst(m map[string]Events) int64 {
	var t int64
	for _, e := range m {
		t += e.CEst()
	}
	return t
}
