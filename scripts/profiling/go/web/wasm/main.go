//go:build js && wasm

// Command cest-wasm is the browser bridge for the CEst analyzer. It exposes a
// single JS function, globalThis.analyzeCest, that runs the same
// cest-analyzer/internal/cest core over file contents the page hands in.
//
// Build:
//
//	GOOS=js GOARCH=wasm go build -o web/static/cest-analyzer.wasm ./web/wasm
//
// There is no filesystem in the browser, so the page reads each
// callgrind.out.* file with the FileReader API and passes its text in; this
// bridge wraps that text in a bytes.Reader Candidate (see internal/cest).
package main

import (
	"bytes"
	"io"
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
	// Block forever: the page calls analyzeCest on demand, so the Go program
	// must stay alive after main returns control to the JS event loop.
	select {}
}
