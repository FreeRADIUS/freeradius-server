package cest

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Candidate is one callgrind.out.* file in a run, named for display and
// opened on demand. The CLI backs Open with os.Open; the browser backs it
// with bytes.NewReader over uploaded contents. Either way the core stays
// free of os and filepath.
type Candidate struct {
	Name string                       // base name, e.g. callgrind.out.1234
	Open func() (io.ReadCloser, error) // fresh stream each call
}

// PickMain returns the candidate with the largest "summary:" Ir counter,
// matching the heuristic of the original shell script. It errors when no
// candidate carries a usable summary line.
func PickMain(cands []Candidate) (Candidate, error) {
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

// FnCost pairs a function name with its self-CEst.
type FnCost struct {
	Name string
	Cost int64
}

// TopNFns returns the n highest self-CEst functions whose name contains pat.
func TopNFns(fnSelf map[string]int64, pat string, n int) []FnCost {
	lpat := strings.ToLower(pat)
	var matches []FnCost
	for name, cost := range fnSelf {
		if strings.Contains(strings.ToLower(name), lpat) {
			matches = append(matches, FnCost{name, cost})
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Cost > matches[j].Cost })
	if len(matches) > n {
		matches = matches[:n]
	}
	return matches
}

// DirResult is one analyzed run, kept for the comparison footer and markdown.
type DirResult struct {
	Label   string     // display label (directory path or run name)
	Main    string     // base name of the chosen main file
	Res     *Result    // parsed totals
	TopData [][]FnCost // top-N functions, indexed by pattern
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
		TopData: make([][]FnCost, len(patterns)),
	}
	for i, pat := range patterns {
		dr.TopData[i] = TopNFns(res.FnSelf, pat, topn)
	}
	return dr, nil
}
