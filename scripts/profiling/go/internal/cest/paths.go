package cest

import (
	"sort"
	"strings"
)

// PathCost is one root-first call path to a function node - the exact form the
// fold box / --fold flag take (e.g. "app_handler/talloc_pool/_talloc") - paired
// with the self-CEst reaching the node along that path.
type PathCost struct {
	Path string
	CEst int64
}

// NodePaths returns, per base function, the distinct root-first call paths that
// reach it, derived from the --separate-callers context names in ctxSelf. A
// context name "base'c1'c2'..." (c1 nearest caller) becomes the path
// ".../c2/c1/base"; contexts that collapse to the same path (e.g. ones that
// differ only in recursion tokens, which callerChain drops) have their self-CEst
// summed. Each function's paths are sorted by CEst descending. A function with
// no caller context is omitted: a bare name folds every call and is just the
// row label, so there is no specific path to offer.
//
// Because a returned path is in the same form foldMatch consumes, copying one
// into the fold box folds exactly that node.
func NodePaths(ctxSelf map[string]Events) map[string][]PathCost {
	type key struct{ base, path string }
	sum := map[key]int64{}
	for name, ev := range ctxSelf {
		chain := callerChain(name) // nearest-first callers, recursion tokens dropped
		if len(chain) == 0 {
			continue
		}
		parts := make([]string, 0, len(chain)+1)
		for i := len(chain) - 1; i >= 0; i-- { // reverse to root-first
			parts = append(parts, chain[i])
		}
		parts = append(parts, BaseName(name)) // target last
		sum[key{BaseName(name), strings.Join(parts, "/")}] += ev.CEst()
	}
	out := make(map[string][]PathCost)
	for k, c := range sum {
		out[k.base] = append(out[k.base], PathCost{Path: k.path, CEst: c})
	}
	for base := range out {
		ps := out[base]
		sort.Slice(ps, func(i, j int) bool {
			if ps[i].CEst != ps[j].CEst {
				return ps[i].CEst > ps[j].CEst
			}
			return ps[i].Path < ps[j].Path
		})
	}
	return out
}
