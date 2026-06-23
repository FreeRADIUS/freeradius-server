//go:build js && wasm

// Command cest-wasm is the browser bridge for the CEst analyzer. It exposes the
// analysis functions on globalThis (see main) and runs the same
// cest-analyzer/internal/cest core over file contents the page hands in.
//
// Build (the UI serves its own copy):
//
//	GOOS=js GOARCH=wasm go build -o web/cest-analyzer.wasm ./web/wasm
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

// jsPaths reads an optional fold-paths argument (a JS array of "a/b/c"
// strings) at args[idx] into root-first call paths. Absent/non-array => nil.
func jsPaths(args []js.Value, idx int) [][]string {
	if len(args) <= idx || args[idx].Type() != js.TypeObject {
		return nil
	}
	a := args[idx]
	out := make([][]string, 0, a.Length())
	for i := 0; i < a.Length(); i++ {
		s := a.Index(i).String()
		if s == "" {
			continue
		}
		out = append(out, strings.Split(s, "/"))
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

// cestReport is the "Download JSON" bridge for the compare UI. It emits the
// rich report schema (per run: total, functions, patterns, categories — each
// with all 9 counters + percent), built with cest.WriteJSON. The compare UI has
// no pattern filter, so the patterns section is empty; categories use the
// defaults.
//
// JS signature: cestReport(runs, topN, patterns?) -> { json } | { error }
// patterns is an optional array of name substrings; empty/absent means the
// functions list is the top-N overall and the patterns section is empty.
func cestReport(this js.Value, args []js.Value) (result any) {
	defer func() {
		if r := recover(); r != nil {
			result = map[string]any{"error": panicMessage(r)}
		}
	}()

	if len(args) < 2 {
		return map[string]any{"error": "cestReport(runs, topN, patterns?): runs and topN required"}
	}
	runsObj := args[0]
	topN := args[1].Int()
	if topN <= 0 {
		topN = 25 // a sane functions count; TopNFnsAny needs a positive bound
	}
	var patterns []string
	if len(args) >= 3 && args[2].Type() == js.TypeObject {
		for i := 0; i < args[2].Length(); i++ {
			patterns = append(patterns, args[2].Index(i).String())
		}
	}

	cats := cest.DefaultCategories()
	var dirs []*cest.DirResult
	for _, label := range jsObjectKeys(runsObj) {
		cands := candidatesFromJS(runsObj.Get(label))
		dr, err := cest.Analyze(label, cands, patterns, cats, topN)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		dirs = append(dirs, dr)
	}
	if len(dirs) == 0 {
		return map[string]any{"error": "no runs supplied"}
	}

	var jsonOut strings.Builder
	if err := cest.WriteJSON(&jsonOut, dirs, patterns, cats, topN); err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{"json": jsonOut.String()}
}

// cestRunCEst is the per-run bridge for the comparison matrix. cestMatrix
// parses every run in one blocking call, which freezes the page (and any
// progress bar) for the whole parse; the compare UI instead calls this once per
// run so it can paint progress and stay responsive between runs. It returns the
// same numbers cestMatrix produces per run — the run's total CEst and each
// function's self CEst — just split out one run at a time. The JS side
// assembles the shared function set and baseline from these.
//
// JS signature: cestRunCEst(files, foldPaths?) -> result
//
//	files: { "callgrind.out.123": "<file text>", ... }   // ONE run's files
//
// Returns on success:
//
//	{
//	  formula, total,
//	  cest:  { "fn": CEst, ... },
//	  paths: { "fn": [ { p: "root/.../fn", c: CEst }, ... ], ... }
//	}
//
// or { error }. paths gives each function's root-first call paths (the fold-box
// form) from the raw --separate-callers graph, for the UI's copy-path popover;
// it is the same regardless of foldPaths.
func cestRunCEst(this js.Value, args []js.Value) (result any) {
	defer func() {
		if r := recover(); r != nil {
			result = map[string]any{"error": panicMessage(r)}
		}
	}()

	if len(args) < 1 {
		return map[string]any{"error": "cestRunCEst(files): 1 arg required"}
	}
	cands := candidatesFromJS(args[0])
	cats := cest.DefaultCategories()
	// No patterns: we want every function's self CEst (the matrix rows).
	dr, err := cest.Analyze("run", cands, nil, cats, 0)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	// Optional arg 1: fold call paths, folded over the context-separated graph.
	self := dr.Res.FnSelf
	if paths := jsPaths(args, 1); len(paths) > 0 {
		self = cest.FoldSelf(dr.Res.CtxSelf, dr.Res.Edges, paths)
	}
	cestObj := make(map[string]any, len(self))
	for name, ev := range self {
		cestObj[name] = ev.CEst()
	}
	// Per-function root-first call paths from the raw context graph (independent
	// of any fold), so the UI can offer them for copy into the fold box. Capped
	// per function to keep the payload small; the JS side unions across runs.
	np := cest.NodePaths(dr.Res.CtxSelf)
	pathsObj := make(map[string]any, len(np))
	for fn, pcs := range np {
		if len(pcs) > 20 {
			pcs = pcs[:20]
		}
		arr := make([]any, len(pcs))
		for i, pc := range pcs {
			arr[i] = map[string]any{"p": pc.Path, "c": pc.CEst}
		}
		pathsObj[fn] = arr
	}
	return map[string]any{
		"formula": cest.Formula,
		"total":   dr.Res.Total.CEst(),
		"cest":    cestObj,
		"paths":   pathsObj,
	}
}

// cestRunDetail is the JS bridge for the per-run detail view (one run's full
// function table). cestMatrix returns only each function's CEst across runs;
// the detail view needs every raw counter for a single run, so this parses one
// run and returns the complete breakdown.
//
// JS signature: cestRunDetail(files) -> result
//
//	files: { "callgrind.out.123": "<file text>", ... }   // ONE run's files
//
// Returns on success:
//
//	{
//	  formula:   "CEst = ...",
//	  total:     { Ir, I1mr, D1mr, D1mw, ILmr, DLmr, DLmw, Bcm, Bim, CEst },
//	  functions: [ { name, Ir, I1mr, ..., Bim, CEst }, ... ]  // descending CEst
//	}
//
// or { error } on failure. The function table is filtered/sorted and the
// per-pattern aggregation table is summed entirely in JS from these counters,
// so changing the PATTERNS field or a sort column needs no re-parse.
func cestRunDetail(this js.Value, args []js.Value) (result any) {
	defer func() {
		if r := recover(); r != nil {
			result = map[string]any{"error": panicMessage(r)}
		}
	}()

	if len(args) < 1 {
		return map[string]any{"error": "cestRunDetail(files): 1 arg required"}
	}
	cands := candidatesFromJS(args[0])
	cats := cest.DefaultCategories()
	// No patterns: the detail view wants every function's counters; pattern
	// filtering and aggregation happen in JS off the full set.
	dr, err := cest.Analyze("detail", cands, nil, cats, 0)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}

	eventsObj := func(e cest.Events) map[string]any {
		return map[string]any{
			"Ir": e.Ir, "I1mr": e.I1mr, "D1mr": e.D1mr, "D1mw": e.D1mw,
			"ILmr": e.ILmr, "DLmr": e.DLmr, "DLmw": e.DLmw,
			"Bcm": e.Bcm, "Bim": e.Bim, "CEst": e.CEst(),
		}
	}

	// Optional arg 1: fold call paths, folded over the context-separated graph.
	self := dr.Res.FnSelf
	if paths := jsPaths(args, 1); len(paths) > 0 {
		self = cest.FoldSelf(dr.Res.CtxSelf, dr.Res.Edges, paths)
	}
	fns := make([]cest.FnEvents, 0, len(self))
	for name, ev := range self {
		fns = append(fns, cest.FnEvents{Name: name, Events: ev})
	}
	// Descending CEst, name as a tiebreaker, so the default order is stable
	// across Go's randomized map iteration.
	sort.Slice(fns, func(i, j int) bool {
		ci, cj := fns[i].Events.CEst(), fns[j].Events.CEst()
		if ci != cj {
			return ci > cj
		}
		return fns[i].Name < fns[j].Name
	})

	funcsOut := make([]any, len(fns))
	for i, fn := range fns {
		o := eventsObj(fn.Events)
		o["name"] = fn.Name
		funcsOut[i] = o
	}

	return map[string]any{
		"formula":   cest.Formula,
		"total":     eventsObj(dr.Res.Total),
		"functions": funcsOut,
	}
}

// cestCompare is the compare-view bridge. It runs internal/cest.CompareCEst over
// the per-run CEst maps the page already parsed (via cestRunCEst), so the
// lowest-CEst baseline / Δ% / spread math lives only in Go (shared with the CLI's
// --compare), not duplicated in JS. No file re-parsing — it takes the cached CEst.
//
// JS signature: cestCompare(runs) -> { functions: [...] } | { error }
//
//	runs: [ { label, total, cest: { "fn": CEst, ... } }, ... ]   // selected runs, in order
//
// Returns functions sorted by spread descending ('new' last); per function:
//
//	{ name, cest: [int,...], deltaPct: [num,...], best: int, spreadPct: num }
//
// cest/deltaPct are aligned to the input runs. deltaPct/spreadPct are +Inf (JS
// Infinity) where a run lacks the function; best is the index of the lowest-CEst
// run. The UI handles sorting by other columns, the patterns filter, and the
// row cap itself off this returned data.
func cestCompare(this js.Value, args []js.Value) (result any) {
	defer func() {
		if r := recover(); r != nil {
			result = map[string]any{"error": panicMessage(r)}
		}
	}()

	if len(args) < 1 || args[0].Type() != js.TypeObject {
		return map[string]any{"error": "cestCompare(runs): runs array required"}
	}
	arr := args[0]
	runs := make([]cest.RunCEst, arr.Length())
	for i := 0; i < arr.Length(); i++ {
		r := arr.Index(i)
		cestObj := r.Get("cest")
		cm := make(map[string]int64)
		for _, name := range jsObjectKeys(cestObj) {
			cm[name] = int64(cestObj.Get(name).Float())
		}
		runs[i] = cest.RunCEst{
			Label: r.Get("label").String(),
			Total: int64(r.Get("total").Float()),
			CEst:  cm,
		}
	}

	rows := cest.CompareCEst(runs)
	out := make([]any, len(rows))
	for i, row := range rows {
		cestArr := make([]any, len(row.CEst))
		for k, c := range row.CEst {
			cestArr[k] = c
		}
		deltaArr := make([]any, len(row.DeltaPct))
		for k, d := range row.DeltaPct {
			deltaArr[k] = d // +Inf -> JS Infinity
		}
		out[i] = map[string]any{
			"name":      row.Name,
			"cest":      cestArr,
			"deltaPct":  deltaArr,
			"best":      row.Best,
			"spreadPct": row.SpreadPct, // +Inf -> JS Infinity
		}
	}
	return map[string]any{"functions": out}
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
	js.Global().Set("cestReport", js.FuncOf(cestReport))
	js.Global().Set("cestRunCEst", js.FuncOf(cestRunCEst))
	js.Global().Set("cestRunDetail", js.FuncOf(cestRunDetail))
	js.Global().Set("cestCompare", js.FuncOf(cestCompare))
	// Block forever: the page calls analyzeCest on demand, so the Go program
	// must stay alive after main returns control to the JS event loop.
	select {}
}
