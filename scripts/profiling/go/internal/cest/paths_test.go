package cest

import "testing"

// TestNodePaths checks that context names become root-first paths, that contexts
// differing only in recursion tokens sum, and that bare (caller-less) names are
// dropped.
func TestNodePaths(t *testing.T) {
	ctx := map[string]Events{
		// _talloc reached two ways; the talloc_pool/app_handler site appears twice,
		// once with a recursion token, so its two costs must sum (10+5=15).
		"_talloc'talloc_pool'app_handler":    ev(10),
		"_talloc'2'talloc_pool'app_handler":  ev(5),
		"_talloc'rbtree_insert'process_post": ev(8),
		// a bare top-level function (no caller context) is omitted.
		"app_handler": ev(99),
	}
	got := NodePaths(ctx)

	tp := got["_talloc"]
	if len(tp) != 2 {
		t.Fatalf("_talloc paths = %d; want 2", len(tp))
	}
	// Sorted by CEst desc: the summed 15 path first.
	if tp[0].Path != "app_handler/talloc_pool/_talloc" || tp[0].CEst != 15 {
		t.Errorf("top path = %q (%d); want app_handler/talloc_pool/_talloc (15)", tp[0].Path, tp[0].CEst)
	}
	if tp[1].Path != "process_post/rbtree_insert/_talloc" || tp[1].CEst != 8 {
		t.Errorf("second path = %q (%d); want process_post/rbtree_insert/_talloc (8)", tp[1].Path, tp[1].CEst)
	}
	if _, ok := got["app_handler"]; ok {
		t.Errorf("bare app_handler should be omitted (no caller context)")
	}
}
