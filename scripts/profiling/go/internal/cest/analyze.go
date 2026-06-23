package cest

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Candidate is one callgrind.out.* file, opened on demand via Open. The CLI
// backs Open with os.Open, the browser with a bytes.Reader, so the core stays
// free of os and filepath.
type Candidate struct {
	Name string                        // base name, e.g. callgrind.out.1234
	Open func() (io.ReadCloser, error) // fresh stream each call
}

// PickMain returns the candidate with the largest "summary:" Ir counter,
// matching the heuristic of the original shell script. It errors when no
// candidate carries a usable summary line.
func PickMain(cands []Candidate) (Candidate, error) {
	// One candidate is the main by definition; skip reading its summary (a full
	// scan of an often-large file) just to confirm a choice with no alternative.
	if len(cands) == 1 {
		return cands[0], nil
	}
	best := Candidate{}
	bestIr := int64(-1)
	found := false
	for _, c := range cands {
		rc, err := c.Open()
		if err != nil {
			continue
		}
		ir := ReadSummaryIr(rc)
		rc.Close()
		if ir > bestIr {
			bestIr, best, found = ir, c, true
		}
	}
	if !found {
		return Candidate{}, fmt.Errorf("no usable callgrind.out.* candidate")
	}
	return best, nil
}

// FnEvents pairs a function name with its self counters.
type FnEvents struct {
	Name   string
	Events Events
}

// TopNFns returns the n highest-CEst functions whose name contains pat.
func TopNFns(fnSelf map[string]Events, pat string, n int) []FnEvents {
	lpat := strings.ToLower(pat)
	var matches []FnEvents
	for name, ev := range fnSelf {
		if strings.Contains(strings.ToLower(name), lpat) {
			matches = append(matches, FnEvents{name, ev})
		}
	}
	sortByCEst(matches)
	if len(matches) > n {
		matches = matches[:n]
	}
	return matches
}

// TopNFnsAny returns the n highest-CEst functions whose name contains any of
// patterns, or the n highest-CEst of all functions when patterns is empty.
// Used for the flat JSON functions list. Each function appears at most once
// (the source map is keyed by name).
func TopNFnsAny(fnSelf map[string]Events, patterns []string, n int) []FnEvents {
	lp := make([]string, len(patterns))
	for i, p := range patterns {
		lp[i] = strings.ToLower(p)
	}
	var matches []FnEvents
	for name, ev := range fnSelf {
		if len(lp) == 0 {
			matches = append(matches, FnEvents{name, ev})
			continue
		}
		lname := strings.ToLower(name)
		for _, p := range lp {
			if strings.Contains(lname, p) {
				matches = append(matches, FnEvents{name, ev})
				break
			}
		}
	}
	sortByCEst(matches)
	if len(matches) > n {
		matches = matches[:n]
	}
	return matches
}

// sortByCEst sorts fns by descending CEst, name ascending as a tiebreaker so
// the order is stable across map-iteration randomness.
func sortByCEst(fns []FnEvents) {
	sort.Slice(fns, func(i, j int) bool {
		ci, cj := fns[i].Events.CEst(), fns[j].Events.CEst()
		if ci != cj {
			return ci > cj
		}
		return fns[i].Name < fns[j].Name
	})
}

// DirResult is one analyzed run, kept for the comparison footer and markdown.
type DirResult struct {
	Label   string       // display label (directory path or run name)
	Main    string       // base name of the chosen main file
	Res     *Result      // parsed totals
	TopData [][]FnEvents // top-N functions, indexed by pattern
}

// Analyze picks the main file from cands, parses it, and computes the
// top-N tables for each pattern. It performs no output.
func Analyze(label string, cands []Candidate, patterns []string, cats []Category, topn int) (*DirResult, error) {
	main, err := PickMain(cands)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	rc, err := main.Open()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	defer rc.Close()

	res, err := Parse(rc, patterns, cats)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}

	dr := &DirResult{
		Label:   label,
		Main:    main.Name,
		Res:     res,
		TopData: make([][]FnEvents, len(patterns)),
	}
	for i, pat := range patterns {
		dr.TopData[i] = TopNFns(res.FnSelf, pat, topn)
	}
	return dr, nil
}
