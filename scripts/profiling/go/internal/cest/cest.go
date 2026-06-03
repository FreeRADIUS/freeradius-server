// Package cest holds the I/O-free Callgrind CEst analysis core.
//
// Nothing in this package touches os, flag, or syscall/js: callers supply
// data through io.Reader / Candidate and receive results as plain structs,
// so the same code compiles for the native CLI, WASI, and browser WASM.
package cest

import "regexp"

// ---------------------------------------------------------------------------
// CEst formula
// ---------------------------------------------------------------------------

// Cost computes the Cycle Estimation from raw Callgrind event counters.
//
//	CEst = Ir + 10*(I1mr+D1mr+D1mw) + 100*(ILmr+DLmr+DLmw) + 10*(Bcm+Bim)
func Cost(ir, i1, d1r, d1w, ilm, dlr, dlw, bcm, bim int64) int64 {
	return ir + 10*(i1+d1r+d1w) + 100*(ilm+dlr+dlw) + 10*(bcm+bim)
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
