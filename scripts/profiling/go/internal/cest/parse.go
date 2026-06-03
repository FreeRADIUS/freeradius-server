package cest

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// Result holds the per-run totals produced by Parse.
type Result struct {
	Total   int64            // total CEst over the whole run
	PatSums []int64          // self-CEst per requested pattern
	FnSelf  map[string]int64 // self-CEst per function name
	CatSums []int64          // self-CEst per category
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
		PatSums: make([]int64, len(patterns)),
		FnSelf:  make(map[string]int64),
		CatSums: make([]int64, len(cats)),
	}
	lp := make([]string, len(patterns))
	for i, p := range patterns {
		lp[i] = strings.ToLower(p)
	}

	nameTable := make(map[string]string)
	curFn := ""
	skipNext := false // true = next cost line is inclusive call-cost; skip it

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

		case strings.HasPrefix(line, "cfn="):
			resolveName(line[4:], nameTable) // register name, don't change curFn

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
			if skipNext {
				// inclusive call-cost line — discard (~24× inflation if counted)
				skipNext = false
				continue
			}

			// Event field offsets (0-based; positions occupy flds[0..1]):
			//   Ir=$3→[2]  I1mr=$6→[5]  D1mr=$7→[6]  D1mw=$8→[7]
			//   ILmr=$9→[8]  DLmr=$10→[9]  DLmw=$11→[10]
			//   Bcm=$13→[12]  Bim=$15→[14]
			ir := getField(flds, 2)
			i1 := getField(flds, 5)
			d1r := getField(flds, 6)
			d1w := getField(flds, 7)
			ilm := getField(flds, 8)
			dlr := getField(flds, 9)
			dlw := getField(flds, 10)
			bcm := getField(flds, 12)
			bim := getField(flds, 14)

			c := Cost(ir, i1, d1r, d1w, ilm, dlr, dlw, bcm, bim)
			res.Total += c

			if curFn == "" {
				continue
			}
			res.FnSelf[curFn] += c
			lf := strings.ToLower(curFn)
			for i, pat := range lp {
				if strings.Contains(lf, pat) {
					res.PatSums[i] += c
				}
			}
			for i, cat := range cats {
				if cat.Match(lf) {
					res.CatSums[i] += c
					break // first-match-wins
				}
			}

		default:
			skipNext = false
		}
	}
	return res, sc.Err()
}
