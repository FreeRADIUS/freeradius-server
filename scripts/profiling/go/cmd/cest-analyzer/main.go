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

	flag.Var(&dirs, "d", "profiling `directory` (repeatable)")
	flag.StringVar(&mdFile, "md", "", "write markdown report to `file`")
	flag.StringVar(&jsonFile, "json", "", "write JSON report to `file`")
	flag.IntVar(&topn, "top", 10, "top-N functions per pattern")
	flag.Parse()

	patterns := flag.Args()
	if len(patterns) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: cest-analyzer [--md <file>] [--json <file>] [--top N] -d <dir> [-d <dir> ...] <pat> [pat ...]")
		os.Exit(1)
	}
	if len(dirs) == 0 {
		dirs = dirFlag{"."}
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
