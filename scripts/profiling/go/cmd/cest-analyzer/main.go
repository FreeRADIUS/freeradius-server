// Command cest-analyzer compares Callgrind cycle-estimate (CEst) cost across
// one or more profiling run result directories.
//
// Usage:
//
//	cest-analyzer [--md <file>] [--top N] -d <dir> [-d <dir> ...] <pat> [pat ...]
//
// Build:   go build -o cest-analyzer ./cmd/cest-analyzer
// WASI:    GOOS=wasip1 GOARCH=wasm go build -o cest-analyzer.wasm ./cmd/cest-analyzer

// The analysis itself lives in cest-analyzer/internal/cest; this file only
// supplies OS-bound I/O: flag parsing, file globbing, and stdout.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cest-analyzer/internal/cest"
)

// dirFlag collects a repeatable -d flag into a slice.
type dirFlag []string

func (d *dirFlag) String() string     { return strings.Join(*d, ", ") }
func (d *dirFlag) Set(v string) error { *d = append(*d, v); return nil }

// listFlag collects a repeatable flag into a slice, splitting each value on
// commas, so --filter a,b and --filter a --filter b both yield [a, b].
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

// candidatesForDir lists callgrind.out.* files in dir as cest.Candidates that
// open lazily via os.Open.
func candidatesForDir(dir string) []cest.Candidate {
	files, _ := filepath.Glob(filepath.Join(dir, "callgrind.out.*"))
	cands := make([]cest.Candidate, 0, len(files))
	for _, f := range files {
		f := f // capture per iteration (go 1.21 loop-var semantics)
		cands = append(cands, cest.Candidate{
			Name: filepath.Base(f),
			Open: func() (io.ReadCloser, error) { return os.Open(f) },
		})
	}
	return cands
}

func main() {
	var dirs dirFlag
	var mdFile string
	var jsonFile string
	var topn int
	var compareMode bool
	var filters listFlag

	flag.Var(&dirs, "d", "profiling `directory` (repeatable)")
	flag.StringVar(&mdFile, "md", "", "write markdown report to `file`")
	flag.StringVar(&jsonFile, "json", "", "write JSON report to `file`")
	flag.IntVar(&topn, "top", 10, "top-N functions per pattern")
	flag.BoolVar(&compareMode, "compare", false, "per-function CEst comparison across runs (the UI compare view); needs >=2 -d dirs")
	flag.Var(&filters, "filter", "function-name `filter`(s) for --compare (repeatable and/or comma-separated; substring, any-match)")
	flag.Parse()

	patterns := flag.Args()
	if len(dirs) == 0 {
		dirs = dirFlag{"."}
	}

	//  --compare: a per-function CEst matrix across the runs, with diffs vs each
	//  function's lowest-CEst run and a spread column - the terminal equivalent of
	//  the UI compare view. --filter (and/or trailing patterns) scope it to
	//  functions whose name matches any entry; --json writes the compare-shaped
	//  JSON, --md does not apply.
	if compareMode {
		if len(dirs) < 2 {
			fmt.Fprintln(os.Stderr, "--compare needs at least two -d directories")
			os.Exit(1)
		}
		//  Scope filters come from --filter plus any trailing positionals, so both
		//  `--filter _talloc,fr_rb` and a bare `_talloc fr_rb` work (and combine).
		scope := append(append(listFlag{}, filters...), patterns...)
		cats := cest.DefaultCategories()
		var results []*cest.DirResult
		for _, d := range dirs {
			dr, err := cest.Analyze(d, candidatesForDir(d), nil, cats, 0)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			results = append(results, dr)
		}
		cest.WriteCompare(os.Stdout, results, scope)
		if jsonFile != "" {
			f, err := os.Create(jsonFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error writing JSON: %v\n", err)
				os.Exit(1)
			}
			if err := cest.WriteCompareJSON(f, results, scope); err != nil {
				f.Close()
				fmt.Fprintf(os.Stderr, "error writing JSON: %v\n", err)
				os.Exit(1)
			}
			if err := f.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "error writing JSON: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Compare JSON written to: %s\n", jsonFile)
		}
		if mdFile != "" {
			fmt.Fprintln(os.Stderr, "note: --md is not supported with --compare; ignoring")
		}
		return
	}

	if len(patterns) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: cest-analyzer [--md <file>] [--json <file>] [--top N] -d <dir> [-d <dir> ...] <pat> [pat ...]")
		fmt.Fprintln(os.Stderr, "   or: cest-analyzer --compare [--filter pat,...] [--json <file>] -d <dir> -d <dir> [-d <dir> ...]")
		os.Exit(1)
	}

	cats := cest.DefaultCategories()
	var results []*cest.DirResult
	for _, d := range dirs {
		dr, err := cest.Analyze(d, candidatesForDir(d), patterns, cats, topn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		cest.WriteReport(os.Stdout, dr, patterns, cats, topn)
		results = append(results, dr)
	}

	if len(results) >= 2 {
		cest.WriteComparison(os.Stdout, results, patterns)
	}

	if mdFile != "" {
		f, err := os.Create(mdFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error writing markdown: %v\n", err)
			os.Exit(1)
		}
		cest.WriteMarkdown(f, results, patterns, cats, topn)
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "error writing markdown: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Markdown report written to: %s\n", mdFile)
	}

	if jsonFile != "" {
		f, err := os.Create(jsonFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error writing JSON: %v\n", err)
			os.Exit(1)
		}
		if err := cest.WriteJSON(f, results, patterns, cats, topn); err != nil {
			f.Close()
			fmt.Fprintf(os.Stderr, "error writing JSON: %v\n", err)
			os.Exit(1)
		}
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "error writing JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("JSON report written to: %s\n", jsonFile)
	}
}
