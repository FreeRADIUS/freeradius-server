package cest

import "strings"

// ---------------------------------------------------------------------------
// Fold self-cost up into callers
// ---------------------------------------------------------------------------
// snipUp is the shared engine for "remove these frames and roll their self-cost
// up into whatever called them": every node where match(name) is true is
// removed and its self-cost folds into the nearest non-matched caller,
// transitively through chains of matched nodes. When a removed node had several
// callers its self-cost is split across them by the per-edge inclusive cost
// (Result.Edges), equal split if there is no edge weight. Total self-cost is
// preserved, except cost that cannot reach any unmatched ancestor (a matched
// root, or a matched-only cycle), which is dropped.
//
// The name-based SnipSelf and the call-path FoldSelf both drive it; they
// only differ in the match predicate.

func lowerAll(p []string) []string {
	out := make([]string, len(p))
	for i, s := range p {
		out[i] = strings.ToLower(s)
	}
	return out
}

// scaleEvents multiplies every counter by f (rounded), for splitting a removed
// node's self-cost across multiple callers.
func scaleEvents(e Events, f float64) Events {
	r := func(v int64) int64 { return int64(float64(v)*f + 0.5) }
	return Events{
		Ir: r(e.Ir), I1mr: r(e.I1mr), D1mr: r(e.D1mr), D1mw: r(e.D1mw),
		ILmr: r(e.ILmr), DLmr: r(e.DLmr), DLmw: r(e.DLmw), Bcm: r(e.Bcm), Bim: r(e.Bim),
	}
}

func snipUp(self map[string]Events, edges map[string]map[string]Events, match func(string) bool) map[string]Events {
	// Reverse edges: callee -> [{caller, weight}], weight = edge inclusive CEst.
	type cw struct {
		caller string
		w      float64
	}
	callers := map[string][]cw{}
	for caller, outs := range edges {
		for callee, incl := range outs {
			callers[callee] = append(callers[callee], cw{caller, float64(incl.CEst())})
		}
	}

	// resolve(f) distributes "one unit entering f" across unmatched ancestors.
	// Unmatched f -> {f:1}. Matched f -> split over its callers by weight,
	// recursing through matched callers. Memoized; the path set breaks
	// matched-only cycles (that fraction is dropped).
	memo := map[string]map[string]float64{}
	var resolve func(string, map[string]bool) map[string]float64
	resolve = func(f string, path map[string]bool) map[string]float64 {
		if !match(f) {
			return map[string]float64{f: 1}
		}
		if m, ok := memo[f]; ok {
			return m
		}
		if path[f] {
			return map[string]float64{} // matched-only cycle: drop
		}
		path[f] = true
		out := map[string]float64{}
		cs := callers[f]
		var tot float64
		for _, c := range cs {
			tot += c.w
		}
		for _, c := range cs {
			var frac float64
			switch {
			case tot > 0:
				frac = c.w / tot
			case len(cs) > 0:
				frac = 1.0 / float64(len(cs)) // no edge weight: split equally
			}
			if frac == 0 {
				continue
			}
			for a, v := range resolve(c.caller, path) {
				out[a] += v * frac
			}
		}
		delete(path, f)
		memo[f] = out
		return out
	}

	result := make(map[string]Events, len(self))
	for name, ev := range self {
		if !match(name) {
			result[name] = result[name].Add(ev)
			continue
		}
		for anc, frac := range resolve(name, map[string]bool{}) {
			result[anc] = result[anc].Add(scaleEvents(ev, frac))
		}
		// dist empty (unrollable) => ev dropped
	}
	return result
}

// SnipSelf folds functions whose name matches any snip pattern (substring,
// case-insensitive) up into their callers. An empty list returns a copy.
func SnipSelf(fnSelf map[string]Events, edges map[string]map[string]Events, snip []string) map[string]Events {
	if len(snip) == 0 {
		out := make(map[string]Events, len(fnSelf))
		for k, v := range fnSelf {
			out[k] = v
		}
		return out
	}
	lsnip := lowerAll(snip)
	return snipUp(fnSelf, edges, func(name string) bool { return matchAny(name, lsnip) })
}
