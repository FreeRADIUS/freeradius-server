package cest

import "strings"

// ---------------------------------------------------------------------------
// Fold: fold a specific call path's function into its caller
// ---------------------------------------------------------------------------
// With callgrind --separate-callers=N, every function node carries its caller
// chain in the name ("base'caller1'caller2'..."), so a *specific* call path can
// be isolated and folded - unlike name-based snipping, which would catch every
// caller of a function. A path is given root-first, target last:
//
//	app_handler/talloc_pool/_talloc
//
// meaning "the _talloc reached via talloc_pool reached via app_handler". The
// target (_talloc) is removed and its self-cost rolls into its caller; other
// _talloc call sites are untouched. Because the cost is already context-
// separated, this is exact (up to the separation depth N). Listing nested paths
// folds transitively (a band of frames collapses to the first un-listed caller).

// isAllDigits reports whether s is a non-empty run of digits - a callgrind
// recursion token ('2, '3, ...), which we skip when reading a node's caller
// chain (C identifiers never start with a digit, so this is unambiguous).
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// callerChain returns a context-tagged name's caller chain, nearest-first, with
// the base function and any recursion tokens dropped:
//
//	"_talloc'2'talloc_pool'app_handler" -> ["talloc_pool", "app_handler"]
func callerChain(name string) []string {
	segs := strings.Split(name, "'")
	out := segs[:0:0]
	for _, s := range segs[1:] { // skip base (segs[0])
		if !isAllDigits(s) {
			out = append(out, s)
		}
	}
	return out
}

// foldMatch returns a predicate matching the context node a path addresses:
// base name == the path's target (last element) and the node's caller chain
// starts with the path's callers nearest-first (path reversed, minus the
// target). A length-1 path (just a target) matches that function in any context.
func foldMatch(paths [][]string) func(string) bool {
	// Precompute (target, wantChain nearest-first) per path.
	type want struct {
		target string
		chain  []string // callers nearest-first
	}
	ws := make([]want, 0, len(paths))
	for _, p := range paths {
		if len(p) == 0 {
			continue
		}
		w := want{target: p[len(p)-1]}
		for i := len(p) - 2; i >= 0; i-- { // reverse the callers -> nearest first
			w.chain = append(w.chain, p[i])
		}
		ws = append(ws, w)
	}
	return func(name string) bool {
		base := BaseName(name)
		var chain []string // lazily computed
		for _, w := range ws {
			if base != w.target {
				continue
			}
			if len(w.chain) == 0 {
				return true // target only: any context
			}
			if chain == nil {
				chain = callerChain(name)
			}
			if len(chain) < len(w.chain) {
				continue
			}
			ok := true
			for i := range w.chain {
				if chain[i] != w.chain[i] {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
		return false
	}
}

// aggregateByBase collapses a context-tagged self-events map to one entry per
// base function (see BaseName), the form the report/compare/UI display.
func aggregateByBase(self map[string]Events) map[string]Events {
	out := make(map[string]Events, len(self))
	for name, ev := range self {
		b := BaseName(name)
		out[b] = out[b].Add(ev)
	}
	return out
}

// FoldSelf folds the given call paths in the context-separated graph and
// returns the resulting per-base-function self-events. With no paths it is just
// aggregateByBase(ctxSelf), i.e. the normal base view.
func FoldSelf(ctxSelf map[string]Events, edges map[string]map[string]Events, paths [][]string) map[string]Events {
	if len(paths) == 0 {
		return aggregateByBase(ctxSelf)
	}
	folded := snipUp(ctxSelf, edges, foldMatch(paths))
	return aggregateByBase(folded)
}

// rebuildResult assembles a DirResult from a base-aggregated self-events map,
// recomputing Total / PatSums / CatSums / TopData so a report or Compare over it
// is consistent. Edges and CtxSelf are carried through.
func rebuildResult(dr *DirResult, base map[string]Events, cats []Category, patterns []string, topn int) *DirResult {
	res := &Result{
		FnSelf:  base,
		PatSums: make([]Events, len(patterns)),
		CatSums: make([]Events, len(cats)),
		Edges:   dr.Res.Edges,
		CtxSelf: dr.Res.CtxSelf,
	}
	lp := lowerAll(patterns)
	for name, ev := range base {
		res.Total = res.Total.Add(ev)
		ln := strings.ToLower(name)
		for i := range lp {
			if strings.Contains(ln, lp[i]) {
				res.PatSums[i] = res.PatSums[i].Add(ev)
			}
		}
		for i := range cats {
			if cats[i].Match(ln) {
				res.CatSums[i] = res.CatSums[i].Add(ev)
				break
			}
		}
	}
	out := &DirResult{Label: dr.Label, Main: dr.Main, Res: res, TopData: make([][]FnEvents, len(patterns))}
	for i, pat := range patterns {
		out.TopData[i] = TopNFns(res.FnSelf, pat, topn)
	}
	return out
}

// Fold returns a copy of dr with the call paths folded (see FoldSelf),
// rebuilt so the report/compare see one consistent per-function view. An empty
// path list yields the normal base-aggregated result.
func Fold(dr *DirResult, cats []Category, patterns []string, topn int, paths [][]string) *DirResult {
	base := FoldSelf(dr.Res.CtxSelf, dr.Res.Edges, paths)
	return rebuildResult(dr, base, cats, patterns, topn)
}
