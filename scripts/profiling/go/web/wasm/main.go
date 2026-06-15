//go:build js && wasm

// Command cest-wasm is the browser bridge for the CEst analyzer. It exposes a
// single JS function, globalThis.analyzeCest, that runs the same
// cest-analyzer/internal/cest core over file contents the page hands in.
//
// Build:
//
//	GOOS=js GOARCH=wasm go build -o web/v1/cest-analyzer.wasm ./web/wasm
//
// There is no filesystem in the browser, so the page reads each
// callgrind.out.* file with the FileReader API and passes its text in; this
// bridge wraps that text in a bytes.Reader Candidate (see internal/cest).
package main

import (
	"bytes"
	"io"
	"sort"
	"strings"
	"syscall/js"

	"cest-analyzer/internal/cest"
)

// jsObjectKeys returns the own enumerable keys of a JS object.
func jsObjectKeys(v js.Value) []string {
	keys := js.Global().Get("Object").Call("keys", v)
	n := keys.Length()
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = keys.Index(i).String()
	}
	return out
}

// candidatesFromJS turns a { filename: contents } JS object into Candidates.
func candidatesFromJS(filesObj js.Value) []cest.Candidate {
	names := jsObjectKeys(filesObj)
	cands := make([]cest.Candidate, 0, len(names))
	for _, name := range names {
		name := name
		data := []byte(filesObj.Get(name).String())
		cands = append(cands, cest.Candidate{
			Name: name,
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(data)), nil
			},
		})
	}
	return cands
}

// analyzeCest is the JS entry point.
//
// JS signature: analyzeCest(runs, patterns, topN)
//
//	runs:     { "<run label>": { "callgrind.out.123": "<file text>", ... }, ... }
//	patterns: ["memset", "rbtree", ...]
//	topN:     number
//
// Returns { text, markdown, json } on success or { error } on failure.
func analyzeCest(this js.Value, args []js.Value) (result any) {
	defer func() {
		if r := recover(); r != nil {
			result = map[string]any{"error": panicMessage(r)}
		}
	}()

	if len(args) < 3 {
		return map[string]any{"error": "analyzeCest(runs, patterns, topN): 3 args required"}
	}
	runsObj := args[0]
	patternsArr := args[1]
	topN := args[2].Int()

	patterns := make([]string, patternsArr.Length())
	for i := range patterns {
		patterns[i] = patternsArr.Index(i).String()
	}
	if len(patterns) == 0 {
		return map[string]any{"error": "at least one pattern is required"}
	}

	cats := cest.DefaultCategories()
	var results []*cest.DirResult
	for _, label := range jsObjectKeys(runsObj) {
		cands := candidatesFromJS(runsObj.Get(label))
		dr, err := cest.Analyze(label, cands, patterns, cats, topN)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		results = append(results, dr)
	}
	if len(results) == 0 {
		return map[string]any{"error": "no runs supplied"}
	}

	var text strings.Builder
	for _, dr := range results {
		cest.WriteReport(&text, dr, patterns, cats, topN)
	}
	if len(results) >= 2 {
		cest.WriteComparison(&text, results, patterns)
	}

	var md strings.Builder
	cest.WriteMarkdown(&md, results, patterns, cats, topN)

	var jsonOut strings.Builder
	if err := cest.WriteJSON(&jsonOut, results, patterns, cats, topN); err != nil {
		return map[string]any{"error": err.Error()}
	}

	return map[string]any{
		"text":     text.String(),
		"markdown": md.String(),
		"json":     jsonOut.String(),
	}
}

// cestMatrix is the JS entry point for the multi-run comparison UI.
//
// JS signature: cestMatrix(runs, topN)
//
//	runs: { "<run label>": { "callgrind.out.123": "<file text>", ... }, ... }
//	topN: number of functions to keep (the shared set, by max CEst across runs;
//	      0 or negative keeps all functions)
//
// Unlike analyzeCest (pattern-centric, per-run top-N), this returns a COMPLETE
// function×run matrix over a single shared function set, so every cell has a
// value: the comparison views (heatmap / trends / divergence) need run B's CEst
// for a function even when that function is not in run B's own top-N.
//
// Returns on success:
//
//	{
//	  formula:   "CEst = ...",
//	  functions: ["fn1", "fn2", ...],           // shared set, max-CEst order
//	  runs: [ { label, mainFile, total, cest: { "fn1": n, ... } }, ... ]
//	}
//
// or { error } on failure. cest is 0 for a function absent from that run.
func cestMatrix(this js.Value, args []js.Value) (result any) {
	defer func() {
		if r := recover(); r != nil {
			result = map[string]any{"error": panicMessage(r)}
		}
	}()

	if len(args) < 2 {
		return map[string]any{"error": "cestMatrix(runs, topN): 2 args required"}
	}
	runsObj := args[0]
	topN := args[1].Int()

	cats := cest.DefaultCategories()

	type runM struct {
		label, main string
		total       int64
		cest        map[string]int64
	}
	var rms []runM
	maxC := map[string]int64{} // per-function max CEst across runs, for the shared set

	for _, label := range jsObjectKeys(runsObj) {
		cands := candidatesFromJS(runsObj.Get(label))
		// No patterns: we want every function's self CEst, not a pattern subset.
		dr, err := cest.Analyze(label, cands, nil, cats, 0)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		cm := make(map[string]int64, len(dr.Res.FnSelf))
		for name, ev := range dr.Res.FnSelf {
			c := ev.CEst()
			cm[name] = c
			if c > maxC[name] {
				maxC[name] = c
			}
		}
		rms = append(rms, runM{label: dr.Label, main: dr.Main, total: dr.Res.Total.CEst(), cest: cm})
	}
	if len(rms) == 0 {
		return map[string]any{"error": "no runs supplied"}
	}

	// Shared function set: the top-N functions by max CEst across runs, so the
	// most significant functions anywhere are the matrix rows.
	type fc struct {
		name string
		c    int64
	}
	fcs := make([]fc, 0, len(maxC))
	for n, c := range maxC {
		fcs = append(fcs, fc{n, c})
	}
	sort.Slice(fcs, func(i, j int) bool {
		if fcs[i].c != fcs[j].c {
			return fcs[i].c > fcs[j].c
		}
		return fcs[i].name < fcs[j].name
	})
	if topN > 0 && len(fcs) > topN {
		fcs = fcs[:topN]
	}

	funcs := make([]any, len(fcs))
	for i, f := range fcs {
		funcs[i] = f.name
	}
	runsOut := make([]any, len(rms))
	for i, rm := range rms {
		cestObj := make(map[string]any, len(fcs))
		for _, f := range fcs {
			cestObj[f.name] = rm.cest[f.name] // 0 if absent
		}
		runsOut[i] = map[string]any{
			"label":    rm.label,
			"mainFile": rm.main,
			"total":    rm.total,
			"cest":     cestObj,
		}
	}
	return map[string]any{
		"formula":   cest.Formula,
		"functions": funcs,
		"runs":      runsOut,
	}
}

// panicMessage renders a recovered panic value as a string for the JS caller.
func panicMessage(v any) string {
	switch e := v.(type) {
	case error:
		return e.Error()
	case string:
		return e
	default:
		return "unknown error"
	}
}

func main() {
	js.Global().Set("analyzeCest", js.FuncOf(analyzeCest))
	js.Global().Set("cestMatrix", js.FuncOf(cestMatrix))
	// Block forever: the page calls analyzeCest on demand, so the Go program
	// must stay alive after main returns control to the JS event loop.
	select {}
}
