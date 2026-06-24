// Command cest-analyzer compares Callgrind cycle-estimate (CEst) cost across
// one or more profiling runs. Runs are either local result directories (-d) or
// runs fetched on demand from a profiling store (-r), so a shareable-URL run
// path can be analyzed without downloading it by hand first.
//
// Usage:
//
//	cest-analyzer [--md <file>] [--top N] -d <dir> [-d <dir> ...] <pat> [pat ...]
//	cest-analyzer --compare -r <store/run/path> -r <store/run/path> [-d <dir> ...]
//
// Build:   go build -o cest-analyzer ./cmd/cest-analyzer
// WASI:    GOOS=wasip1 GOARCH=wasm go build -o cest-analyzer.wasm ./cmd/cest-analyzer
//          (the WASI target can't open network sockets, so -r is native-only)

// The analysis itself lives in cest-analyzer/internal/cest; this file only
// supplies I/O: flag parsing, file globbing, store fetching, and stdout.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cest-analyzer/internal/cest"
)

// defaultStoreURL is the profiling store used for -r runs when neither
// --store-url nor $CEST_STORE_URL is set. Matches the web UI's default store.
const defaultStoreURL = "https://cinfra-ca.testdev.inkbridge.io/profiling"

// runSpec is one requested run, in command-line order. A local directory (-d)
// or a remote store run (-r), whose val is a path under the store base (as in a
// shareable-URL run path) or a full URL under that base.
type runSpec struct {
	remote bool
	val    string
}

// runFlag is the flag.Value behind both -d and -r. Both write into one shared,
// ordered slice (via the specs pointer) so the order runs appear on the command
// line is preserved across the two flags — which is the compare column order.
type runFlag struct {
	specs  *[]runSpec
	remote bool
}

func (f *runFlag) String() string { return "" }
func (f *runFlag) Set(v string) error {
	if v = strings.TrimSpace(v); v != "" {
		*f.specs = append(*f.specs, runSpec{remote: f.remote, val: v})
	}
	return nil
}

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

// runInput is a resolved run ready for cest.Analyze: a display label and the
// (lazy) candidate files behind it, regardless of local or remote origin.
type runInput struct {
	label string
	cands []cest.Candidate
}

// buildInputs resolves every runSpec into a runInput, preserving order. Remote
// runs share a single store manifest (fetched on first use) that maps each run
// path to its callgrind.out.* file names. With cacheDir set, remote files are
// downloaded there once and reused; otherwise they stream straight from HTTP.
func buildInputs(specs []runSpec, storeURL, cacheDir string) ([]runInput, error) {
	var manifest map[string][]string // run path -> callgrind file names; nil until first -r
	inputs := make([]runInput, 0, len(specs))
	for _, s := range specs {
		if !s.remote {
			inputs = append(inputs, runInput{label: s.val, cands: candidatesForDir(s.val)})
			continue
		}
		runPath, err := storeRunPath(s.val, storeURL)
		if err != nil {
			return nil, err
		}
		if manifest == nil {
			m, err := fetchManifest(storeURL)
			if err != nil {
				return nil, fmt.Errorf("fetching store manifest from %s/manifest.json: %w", storeURL, err)
			}
			manifest = m
		}
		files := manifest[runPath]
		if len(files) == 0 {
			return nil, fmt.Errorf("run %q not found on the store, or it has no callgrind.out.* files", runPath)
		}
		inputs = append(inputs, runInput{label: runPath, cands: remoteCandidates(storeURL, runPath, files, cacheDir)})
	}
	return inputs, nil
}

// storeRunPath turns a -r value into a store-relative run path. A bare path is
// taken as-is; a full URL must sit under storeURL (so all runs share one store
// and one manifest) and is reduced to its path.
func storeRunPath(val, storeURL string) (string, error) {
	if !strings.HasPrefix(val, "http://") && !strings.HasPrefix(val, "https://") {
		return strings.Trim(val, "/"), nil
	}
	if !strings.HasPrefix(val, storeURL+"/") {
		return "", fmt.Errorf("run URL %q is not under the store base %q (pass the run path, or set --store-url)", val, storeURL)
	}
	return strings.Trim(strings.TrimPrefix(val, storeURL+"/"), "/"), nil
}

// httpClient is shared by the manifest and file fetches; a generous timeout
// covers large callgrind.out files on a slow link.
var httpClient = &http.Client{Timeout: 120 * time.Second}

// httpGet returns the response body (a ReadCloser the caller must close) for a
// 200 response, or an error for transport failures and non-200 statuses.
func httpGet(url string) (io.ReadCloser, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return resp.Body, nil
}

// fetchManifest loads storeURL/manifest.json and maps each run path to its
// callgrind.out.* file names (the same manifest the web UI reads).
func fetchManifest(storeURL string) (map[string][]string, error) {
	body, err := httpGet(storeURL + "/manifest.json")
	if err != nil {
		return nil, err
	}
	defer body.Close()
	var doc struct {
		Runs []struct {
			Path  string   `json:"path"`
			Files []string `json:"files"`
		} `json:"runs"`
	}
	if err := json.NewDecoder(body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding manifest: %w", err)
	}
	m := make(map[string][]string, len(doc.Runs))
	for _, r := range doc.Runs {
		var cg []string
		for _, f := range r.Files {
			if strings.HasPrefix(f, "callgrind.out") {
				cg = append(cg, f)
			}
		}
		m[r.Path] = cg
	}
	return m, nil
}

// remoteCandidates builds lazy candidates for a store run's files. Each Open
// streams the file over HTTP, or (with cacheDir set) downloads it once to disk
// and serves it from there on this and future invocations.
func remoteCandidates(storeURL, runPath string, files []string, cacheDir string) []cest.Candidate {
	cands := make([]cest.Candidate, 0, len(files))
	for _, name := range files {
		name := name // capture per iteration
		url := storeURL + "/" + runPath + "/" + name
		open := func() (io.ReadCloser, error) { return httpGet(url) }
		if cacheDir != "" {
			local := filepath.Join(cacheDir, filepath.FromSlash(runPath), name)
			open = func() (io.ReadCloser, error) { return openCached(local, url) }
		}
		cands = append(cands, cest.Candidate{Name: name, Open: open})
	}
	return cands
}

// openCached returns the local file if already downloaded, else fetches url to
// local (atomically, via a .tmp rename) and returns the freshly written file.
func openCached(local, url string) (io.ReadCloser, error) {
	if f, err := os.Open(local); err == nil {
		return f, nil
	}
	body, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		return nil, err
	}
	tmp := local + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(f, body); err != nil {
		f.Close()
		os.Remove(tmp)
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	if err := os.Rename(tmp, local); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	return os.Open(local)
}

func main() {
	var specs []runSpec
	var mdFile string
	var jsonFile string
	var topn int
	var compareMode bool
	var filters listFlag
	var fold listFlag
	var storeURL string
	var cacheDir string

	flag.Var(&runFlag{&specs, false}, "d", "profiling `directory` (repeatable; local path)")
	flag.Var(&runFlag{&specs, true}, "r", "store `run` to fetch + analyze (repeatable; path under --store-url, e.g. branch/sha/run/suite/test, or a full URL)")
	flag.StringVar(&storeURL, "store-url", "", "base URL of the profiling store for -r runs (default $CEST_STORE_URL, else "+defaultStoreURL+")")
	flag.StringVar(&cacheDir, "cache-dir", "", "download -r run files into this `dir` and reuse them (default: stream without saving)")
	flag.StringVar(&mdFile, "md", "", "write markdown report to `file`")
	flag.StringVar(&jsonFile, "json", "", "write JSON report to `file`")
	flag.IntVar(&topn, "top", 10, "top-N functions per pattern")
	flag.BoolVar(&compareMode, "compare", false, "per-function CEst comparison across runs (the UI compare view); needs >=2 runs")
	flag.Var(&filters, "filter", "function-name `filter`(s) for --compare (repeatable and/or comma-separated; substring, any-match)")
	flag.Var(&fold, "fold", "fold a call `path` (root-first, slash-separated, target last) into its caller; repeatable and/or comma-separated; needs --separate-callers profiling; e.g. app_handler/talloc_pool/_talloc")
	flag.Parse()

	patterns := flag.Args()

	// Resolve the store base: explicit flag wins, then $CEST_STORE_URL, then the
	// built-in default. Trailing slashes are trimmed so URL joins are clean.
	if storeURL == "" {
		storeURL = os.Getenv("CEST_STORE_URL")
	}
	if storeURL == "" {
		storeURL = defaultStoreURL
	}
	storeURL = strings.TrimRight(storeURL, "/")

	// No runs given at all: keep the old default of the current directory.
	if len(specs) == 0 {
		specs = []runSpec{{remote: false, val: "."}}
	}

	inputs, err := buildInputs(specs, storeURL, cacheDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Parse --fold entries (each "a/b/c") into root-first call paths.
	var foldPaths [][]string
	for _, e := range fold {
		foldPaths = append(foldPaths, strings.Split(e, "/"))
	}

	//  --compare: a per-function CEst matrix across the runs, with diffs vs each
	//  function's lowest-CEst run and a spread column - the terminal equivalent of
	//  the UI compare view. --filter (and/or trailing patterns) scope it to
	//  functions whose name matches any entry; --json writes the compare-shaped
	//  JSON, --md does not apply.
	if compareMode {
		if len(inputs) < 2 {
			fmt.Fprintln(os.Stderr, "--compare needs at least two runs (-d and/or -r)")
			os.Exit(1)
		}
		//  Scope filters come from --filter plus any trailing positionals, so both
		//  `--filter _talloc,fr_rb` and a bare `_talloc fr_rb` work (and combine).
		scope := append(append(listFlag{}, filters...), patterns...)
		cats := cest.DefaultCategories()
		var results []*cest.DirResult
		for _, in := range inputs {
			dr, err := cest.Analyze(in.label, in.cands, nil, cats, 0)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			if len(foldPaths) > 0 {
				dr = cest.Fold(dr, cats, nil, 0, foldPaths) // fold paths before comparing
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
		fmt.Fprintln(os.Stderr, "   or: cest-analyzer --compare [--filter pat,...] [--json <file>] -d <dir>|-r <run> -d <dir>|-r <run> [...]")
		fmt.Fprintln(os.Stderr, "  -r <run> fetches a run from --store-url (default "+defaultStoreURL+")")
		os.Exit(1)
	}

	cats := cest.DefaultCategories()
	var results []*cest.DirResult
	for _, in := range inputs {
		dr, err := cest.Analyze(in.label, in.cands, patterns, cats, topn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if len(foldPaths) > 0 {
			dr = cest.Fold(dr, cats, patterns, topn, foldPaths) // fold paths before reporting
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
