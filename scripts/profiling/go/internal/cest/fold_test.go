package cest

import "testing"

// TestFoldPath checks that a path folds only the targeted call site.
// Two paths reach _talloc:
//
//	app_handler -> talloc_pool -> _talloc   (self 12)
//	app_handler -> other_pool  -> _talloc   (self 20)
//
// Coalescing app_handler/talloc_pool/_talloc folds only the first into
// talloc_pool; the other_pool _talloc is untouched.
func TestFoldPath(t *testing.T) {
	ctx := map[string]Events{
		"app_handler":                     ev(5),
		"talloc_pool'app_handler":         ev(8),
		"_talloc'talloc_pool'app_handler": ev(12),
		"other_pool'app_handler":          ev(3),
		"_talloc'other_pool'app_handler":  ev(20),
	}
	edges := map[string]map[string]Events{
		"app_handler":             {"talloc_pool'app_handler": ev(20), "other_pool'app_handler": ev(23)},
		"talloc_pool'app_handler": {"_talloc'talloc_pool'app_handler": ev(12)},
		"other_pool'app_handler":  {"_talloc'other_pool'app_handler": ev(20)},
	}

	// Baseline (no fold): _talloc base aggregates both sites = 32.
	if c := FoldSelf(ctx, edges, nil)["_talloc"].CEst(); c != 32 {
		t.Fatalf("baseline _talloc = %d; want 32", c)
	}

	base := FoldSelf(ctx, edges, [][]string{{"app_handler", "talloc_pool", "_talloc"}})
	if c := base["_talloc"].CEst(); c != 20 {
		t.Errorf("_talloc after fold = %d; want 20 (other_pool site only)", c)
	}
	if c := base["talloc_pool"].CEst(); c != 20 { // 8 + folded 12
		t.Errorf("talloc_pool after fold = %d; want 20", c)
	}
	if c := base["app_handler"].CEst(); c != 5 {
		t.Errorf("app_handler = %d; want 5 (unchanged)", c)
	}
	if tot := totalCEst(base); tot != 48 {
		t.Errorf("total = %d; want 48 (preserved)", tot)
	}

	// A length-1 path folds the function in every context: both sites fold up.
	all := FoldSelf(ctx, edges, [][]string{{"_talloc"}})
	if _, ok := all["_talloc"]; ok {
		t.Errorf("_talloc should be fully folded away with a bare-target path")
	}
	if c := all["talloc_pool"].CEst(); c != 20 {
		t.Errorf("talloc_pool = %d; want 20", c)
	}
	if c := all["other_pool"].CEst(); c != 23 { // 3 + folded 20
		t.Errorf("other_pool = %d; want 23", c)
	}
}
