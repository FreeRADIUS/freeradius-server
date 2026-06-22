// Package cest holds the I/O-free Callgrind CEst analysis core.
//
// Nothing in this package touches os, flag, or syscall/js: callers supply
// data through io.Reader / Candidate and receive results as plain structs,
// so the same code compiles for the native CLI, WASI, and browser WASM.
package cest

import (
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// Event counters + CEst formula
// ---------------------------------------------------------------------------

// Events holds the raw Callgrind counters that CEst is built from.
type Events struct {
	Ir   int64 // instruction reads
	I1mr int64 // L1 instruction-cache read misses
	D1mr int64 // L1 data-cache read misses
	D1mw int64 // L1 data-cache write misses
	ILmr int64 // last-level instruction-cache read misses
	DLmr int64 // last-level data-cache read misses
	DLmw int64 // last-level data-cache write misses
	Bcm  int64 // conditional-branch mispredictions
	Bim  int64 // indirect-branch mispredictions
}

// CEst computes the Cycle Estimation from the counters.
//
// Equation taken from QCachegrind/KCachegrind 0.8.0 implementation:
// CEst = Ir + 10*(I1mr+D1mr+D1mw) + 100*(ILmr+DLmr+DLmw) + 10*(Bcm+Bim)
func (e Events) CEst() int64 {
	return e.Ir + 10*(e.I1mr+e.D1mr+e.D1mw) + 100*(e.ILmr+e.DLmr+e.DLmw) + 10*(e.Bcm+e.Bim)
}

// Add returns the field-wise sum of e and o.
func (e Events) Add(o Events) Events {
	return Events{
		Ir:   e.Ir + o.Ir,
		I1mr: e.I1mr + o.I1mr,
		D1mr: e.D1mr + o.D1mr,
		D1mw: e.D1mw + o.D1mw,
		ILmr: e.ILmr + o.ILmr,
		DLmr: e.DLmr + o.DLmr,
		DLmw: e.DLmw + o.DLmw,
		Bcm:  e.Bcm + o.Bcm,
		Bim:  e.Bim + o.Bim,
	}
}

// BaseName strips a callgrind --separate-callers / --separate-recs context from a
// function name: everything from the first apostrophe on (the recursion level and
// the caller chain) is dropped, leaving the bare function. Names without a context
// (no apostrophe) are returned unchanged, so this is a no-op on profiles collected
// without separation.
//
//	"_talloc'talloc_pool'app_handler"  -> "_talloc"
//	"fr_pair_list_free'2'..."          -> "fr_pair_list_free"
//	"main"                             -> "main"
func BaseName(name string) string {
	if i := strings.IndexByte(name, '\''); i >= 0 {
		return name[:i]
	}
	return name
}

// Pct returns num/den as a percentage, or 0 when den is 0.
func Pct(num, den int64) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den) * 100
}

// ---------------------------------------------------------------------------
// Category configuration
// ---------------------------------------------------------------------------

// Category groups function names by a case-insensitive regexp.
type Category struct {
	Label string
	re    *regexp.Regexp
}

// Match reports whether s falls in the category.
func (c Category) Match(s string) bool { return c.re.MatchString(s) }

// CI builds a Category whose regexp matches case-insensitively.
func CI(label, pattern string) Category {
	return Category{Label: label, re: regexp.MustCompile(`(?i)` + pattern)}
}

// DefaultCategories returns the built-in "where the cost goes" breakdown.
// The first matching category wins, so list the most specific first.
func DefaultCategories() []Category {
	return []Category{
		CI("memset (zeroing)", `memset`),
		CI("memmove/memcpy", `mem(?:move|cpy)`),
		CI("printf / string fmt", `printf_buffer|vsnprintf|vasprintf|itoa|snprintf_chk`),
		CI("malloc family (libc)", `^malloc$|^free$|_int_malloc|_int_free|_int_realloc|^realloc$`),
		CI("sha256 / crypto", `sha256|evp_|openssl_|crypto_|hmac|kdf_|evp_md`),
		CI("pthread / locking", `pthread_rwlock|pthread_getspecific|thread_`),
	}
}
