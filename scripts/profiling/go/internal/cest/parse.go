package cest

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// Result holds the per-run totals produced by Parse. Each field accumulates
// the full Events counter set, so any component (or the derived CEst) can be
// read back; Total carries every component, which lets later stages
// compute a per-metric percentage share.
type Result struct {
	Total   Events            // counters summed over the whole run
	PatSums []Events          // self counters per requested pattern
	FnSelf  map[string]Events // self counters per function name
	CatSums []Events          // self counters per category
	// Edges is the call graph: Edges[caller][callee] is the inclusive cost of
	// caller's calls into callee (the cost line that follows calls=). With
	// --separate-callers the caller/callee keys are context-tagged names, so this
	// is the per-call-context graph used by --fold.
	Edges map[string]map[string]Events
	// CtxSelf is self cost per *context-tagged* function name (the raw fn= name,
	// keeping the --separate-callers caller chain). FnSelf above is the same cost
	// aggregated by BaseName, which is what the report/compare/UI show by default;
	// CtxSelf + Edges retain the call-path detail that --fold needs.
	CtxSelf map[string]Events
}

// ---------------------------------------------------------------------------
// Callgrind name-compression resolver
// ---------------------------------------------------------------------------
// fn= and cfn= share one symbol table.  "(ID) real name" registers the ID;
// "(ID)" alone looks it up.  Names registered as callees (cfn=) may appear
// later as fn= cost owners.

func resolveName(s string, table map[string]string) string {
	if len(s) == 0 || s[0] != '(' {
		return s
	}
	end := strings.IndexByte(s, ')')
	if end < 0 {
		return s
	}
	id := s[1:end]
	rest := strings.TrimSpace(s[end+1:])
	if rest != "" {
		table[id] = rest
	}
	return table[id] // "" if not yet registered
}

// getField returns fields[i] as int64, or 0 if out of bounds.
func getField(fields []string, i int) int64 {
	if i >= len(fields) {
		return 0
	}
	v, _ := strconv.ParseInt(fields[i], 10, 64)
	return v
}

// parseEvents reads the 9 raw counters from a callgrind cost line's fields.
// Event field offsets (0-based; positions occupy flds[0..1]):
//
//	Ir=$3->[2]  I1mr=$6->[5]  D1mr=$7->[6]  D1mw=$8->[7]
//	ILmr=$9->[8]  DLmr=$10->[9]  DLmw=$11->[10]  Bcm=$13->[12]  Bim=$15->[14]
func parseEvents(flds []string) Events {
	return Events{
		Ir:   getField(flds, 2),
		I1mr: getField(flds, 5),
		D1mr: getField(flds, 6),
		D1mw: getField(flds, 7),
		ILmr: getField(flds, 8),
		DLmr: getField(flds, 9),
		DLmw: getField(flds, 10),
		Bcm:  getField(flds, 12),
		Bim:  getField(flds, 14),
	}
}

// isDataLine reports whether the first byte looks like a callgrind cost line.
// Callgrind positions may be decimal, hex (0x…), or compressed (*  +off  -off).
func isDataLine(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
		c == 'x' || c == '*' || c == '+' || c == '-'
}

// ReadSummaryIr returns the "summary:" Ir counter, or -1 if none is found.
// Used to pick the largest callgrind.out.* file in a run.
func ReadSummaryIr(r io.Reader) int64 {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4<<20), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "summary:") {
			if fields := strings.Fields(line); len(fields) >= 2 {
				v, _ := strconv.ParseInt(fields[1], 10, 64)
				return v
			}
		}
	}
	return -1
}

// Parse reads one callgrind.out.* stream and accumulates self-CEst totals.
func Parse(r io.Reader, patterns []string, cats []Category) (*Result, error) {
	res := &Result{
		PatSums: make([]Events, len(patterns)),
		FnSelf:  make(map[string]Events),
		CatSums: make([]Events, len(cats)),
		Edges:   make(map[string]map[string]Events),
		CtxSelf: make(map[string]Events),
	}
	lp := make([]string, len(patterns))
	for i, p := range patterns {
		lp[i] = strings.ToLower(p)
	}

	nameTable := make(map[string]string)
	curFn := ""
	curCallee := ""  // most recent cfn= callee, for capturing caller->callee edges
	skipNext := false // true = next cost line is inclusive call-cost; record edge + skip

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4<<20), 4<<20)

	for sc.Scan() {
		line := sc.Text()
		if len(line) == 0 {
			skipNext = false
			continue
		}

		switch {
		case strings.HasPrefix(line, "fn="):
			curFn = resolveName(line[3:], nameTable)
			curCallee = ""

		case strings.HasPrefix(line, "cfn="):
			curCallee = resolveName(line[4:], nameTable) // edge callee; curFn unchanged

		case strings.HasPrefix(line, "calls="):
			skipNext = true

		case strings.HasPrefix(line, "cob="),
			strings.HasPrefix(line, "cfi="),
			strings.HasPrefix(line, "cfl="):
			// cross-object/file directives — leave skipNext unchanged

		case isDataLine(line[0]):
			flds := strings.Fields(line)
			// With "positions: instr line" the layout is:
			//   flds[0]=instr  flds[1]=line  flds[2..]=events
			// flds[2] (Ir) must be a non-negative integer; if not, it's
			// not a cost line (e.g. a header we haven't seen the events= for).
			if len(flds) < 3 {
				skipNext = false
				continue
			}
			if _, e := strconv.ParseUint(flds[2], 10, 64); e != nil {
				skipNext = false
				continue
			}
			ev := parseEvents(flds)
			if skipNext {
				// inclusive call-cost line: record the curFn->curCallee edge (the
				// per-edge weight --fold uses), then discard from self accounting
				// (~24x inflation if counted as self).
				skipNext = false
				if curFn != "" && curCallee != "" {
					if res.Edges[curFn] == nil {
						res.Edges[curFn] = make(map[string]Events)
					}
					res.Edges[curFn][curCallee] = res.Edges[curFn][curCallee].Add(ev)
				}
				continue
			}

			res.Total = res.Total.Add(ev)

			if curFn == "" {
				continue
			}
			// FnSelf is aggregated by base function (collapsing --separate-callers
			// context + recursion) so the report/compare/UI see one row per
			// function; CtxSelf keeps the per-context cost for --fold.
			base := BaseName(curFn)
			res.FnSelf[base] = res.FnSelf[base].Add(ev)
			res.CtxSelf[curFn] = res.CtxSelf[curFn].Add(ev)
			lf := strings.ToLower(base)
			for i, pat := range lp {
				if strings.Contains(lf, pat) {
					res.PatSums[i] = res.PatSums[i].Add(ev)
				}
			}
			for i, cat := range cats {
				if cat.Match(lf) {
					res.CatSums[i] = res.CatSums[i].Add(ev)
					break // first-match-wins
				}
			}

		default:
			skipNext = false
		}
	}
	return res, sc.Err()
}
