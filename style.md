# FreeRADIUS C style guide

The rules below are conventions used in the `src/` directory. When in doubt, match the surrounding file.

## Formatting

- **Indentation**: hard tabs. One tab per level. Don't mix tabs and spaces. Continuation lines align with tabs followed by spaces if needed.
- **Line length**: aim for ~120 characters. Tables, initialiser arrays, and long function declarations may run longer when it improves readability (see `src/lib/util/value.c` for examples that exceed 150 cols).
- **Braces**: K&R. Opening brace on the same line as the control statement; function bodies open on the line after the signature.
  ```c
  void fr_pair_list_init(fr_pair_list_t *list)
  {
      if (cond) {
          ...
      } else {
          ...
      }
  }
  ```
- **Single-statement bodies**: braces are optional, but pick one and stay consistent within a function. Multi-line bodies always brace.
- **Switch**: `case` aligns with `switch`; statements indent one level under `case`.
- **Spaces**:
  - Around all binary operators: `a + b`, `x == y`.
  - After commas, never before.
  - After keywords: `if (x)`, `while (x)`, `for (;;)`.
  - Not inside call parens: `foo(x)`, never `foo( x )`.
- **Pointer asterisk binds to the variable**: `char *p`, not `char* p` or `char * p`.
- **`const` after the type**: `char const *p` is preferred. `const char *p` exists in older code but new code uses `char const *`.
- **Trailing commas** in enums and array initialisers are allowed and common.
- **Comments**: `/* ... */` are most commonly used. Rarely `//`. Doxygen blocks use `/** ... */`.
- **`#define` indentation**: nested preprocessor directives indent the `#` with a leading space: `# define`.

## Naming

- **Functions**: `snake_case`. Public/exported functions use the `fr_` prefix and a subsystem prefix: `fr_pair_list_init`, `fr_sbuff_out`, `fr_dict_attr_by_name`.
- **Static functions**: `snake_case` with no `fr_` prefix; an internal helper that backs a public function is often `_fr_<name>` (leading underscore).
- **Types and typedefs**: `snake_case` with `_t` suffix; library types take an `fr_` prefix: `fr_pair_t`, `fr_dict_attr_t`, `fr_sbuff_t`. Module-local types may omit the `fr_` prefix.
- **Macros / compile-time constants**: `SCREAMING_SNAKE_CASE`: `FR_TYPE_STRING`, `SBUFF_CHAR_CLASS`. Function-like macros that act like ordinary functions may be lowercase (e.g. `fr_assert(...)`).
- **Enum members**: `ALL_CAPS_NAMES` with a shared prefix that identifies the enum: `FR_TYPE_NULL`, `FR_TYPE_STRING`, etc.
- **Struct fields**: `snake_case`.
- **Files**: `snake_case.c` / `snake_case.h`. No hyphens.
- **Conventional variable names** - use these by reflex:
  - `ctx` - `TALLOC_CTX *`
  - `da` - `fr_dict_attr_t const *`
  - `len` - length (`size_t` or unsigned)
  - `request` - `request_t *`
  - `mctx` - `module_ctx_t const *`
  - `inst` - module instance data
  - `t` - module thread-instance data
  - `p`, `end` - byte pointers walking a buffer
  - `sbuff` / `dbuff` - sbuff/dbuff parsers
  - `out`, `in` - output / input sbuff or sbuff-pair function arguments
  - `slen` - `fr_slen_t` or `ssize_t` parse result
  - `vb` or `box` - `fr_value_box_t *`
  - `vp` - `fr_pair_t *`
  - `vpt` - `tmpl_t *`

## Headers and file layout

Every `.c` file begins with:

1. **License boilerplate** as a `/* ... */` block. LGPL for `src/lib/`, GPL for `src/modules/` and `src/bin/`.
2. **Doxygen file header**:
   ```c
   /** One-line description
    *
    * @file path/relative/to/repo/foo.c
    *
    * @copyright YYYY Author Name (email)
    */
   ```
3. **`RCSID("$Id$")`** macro - required.
4. Optional **private-section defines** (e.g. `#define _PAIR_PRIVATE 1`) before includes.
5. **Includes**: system headers first, then `<freeradius-devel/...>` headers grouped by subsystem, roughly alphabetical within a group.

Every `.h` file begins with `#pragma once`, then license, then includes. **Never** use `#ifndef FOO_H` guards - `#pragma once` is the project convention.

Forward typedefs go near the top of headers; full struct definitions live in `.c` files or private `_priv.h` headers when the type should be opaque.

## Code patterns

### Memory

- **Talloc everywhere**: `talloc`, `talloc_zero`, `talloc_array`, `talloc_steal`. Always parent allocations under a meaningful context - usually the longest-lived object that should own the memory.
- **`MEM(x)`** wraps an allocation that must not fail: `MEM(vp = talloc(ctx, fr_pair_t));`. On failure it logs OUT OF MEMORY and aborts. Use it for unrecoverable allocations; don't use it when the caller can recover gracefully.
- **Talloc thread safety**: a hierarchy is owned by exactly one thread. Don't share talloc parents across threads without external locks.

### Error handling

- **Integer-returning functions**: `0` on success, `-1` on error. A few cases use `-2` / negative offsets to encode position; document those.
- **Pointer-returning functions**: `NULL` on error.
- **`bool`-returning functions**: `true` on success.
- **Error messages**: call `fr_strerror_const("...")` for literal strings, `fr_strerror_printf("fmt", ...)` for formatted ones. Push extra context with `fr_strerror_printf_push(...)`. Do **not** log directly from a library function - let the caller decide.
- **NULL checks**: prefer `if (!ptr)` over `if (ptr == NULL)`. Both are accepted; the negation form is more common.

### Cleanup with `goto`

The standard pattern for multi-step allocation that needs to unwind on failure:

```c
foo_t *f;

f = talloc(ctx, foo_t);
if (!f) return NULL;

if (step_one(f) < 0) goto error;
if (step_two(f) < 0) goto error;

return f;

error:
    talloc_free(f);
    return NULL;
```

Common label names: `error`, `fail`, `done`, `oom`. Pick names that describe the *exit condition*, not the line number. Labels go at column 0 (or one tab indent) - typically just before the cleanup code at the end of the function.

### Compiler hints

- `CC_HINT(nonnull)` / `CC_HINT(nonnull(N))` - argument N (1-indexed) is non-NULL. Use on public APIs to catch caller mistakes.
- `CC_HINT(warn_unused_result)` - caller must consume the return value.
- `CC_HINT(always_inline)` - for tiny helpers in hot paths.
- `CC_HINT(flag_enum)` - enum is a bitfield.
- `UNUSED` - parameter is intentionally unused.
- `NDEBUG_UNUSED` - parameter is intentionally unused in normal builds, used only for `fr_assert(...)` in `NDEBUG` builds.

### Diagnostic pragmas

- `DIAG_OFF(name)` / `DIAG_ON(name)` for localised warning suppression. Pair them tightly around the offending construct; never disable a diagnostic file-wide.

### Doxygen on public functions

Required on every non-static function. Minimum:

```c
/** One-line summary
 *
 * Optional longer description.
 *
 * @param[in]  arg   what it is.
 * @param[out] out   what gets written.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
```

Useful extras: `@note`, `@hidecallergraph`, `@copybrief`, `@see`.

## Specific gotchas

- **Signed `char` as array index**: never. `arr[c]` where `c` is `char` and the byte is ≥ 0x80 reads OOB on signed-char platforms. Cast to `(uint8_t)` first, or use a helper like `fr_sbuff_uint8()` instead of `fr_sbuff_char()`.
- **`ctype.h` functions** (`tolower`, `isspace`, `isalpha`, …): pass `(uint8_t)c`, not `c`. Negative `int` arguments are undefined behaviour.
- **Dictionary attributes** - never look up by number with a literal. Use the `fr_dict_attr_autoload_t` mechanism so the dictionary can change without breaking code.
- **Module instance data** is read-only after `instantiate` (mprotected). Mutable runtime state belongs in thread-instance data (`mctx->thread`), not `mi->data`.
- **No bare `malloc`/`free`** in new code - talloc only. The only exception is a handful of system-call wrappers.
- **No magic numbers** in code. Name the constant, or use a dictionary lookup, or both.

## Quick checklist for new code

- Tabs, K&R, `*` next to the variable, `char const *`.
- `fr_` prefix on exported APIs, `snake_case_t` types.
- `#pragma once` in headers, `RCSID` in `.c` files.
- Doxygen block on every public function.
- Cast to `(uint8_t)` before using a `char` as an array index or `ctype.h` argument.
- Talloc all the things; `MEM()` for must-succeed allocations.
- `fr_strerror_*` for diagnostics; never `fprintf(stderr, ...)` from library code.
- Errors return `-1` / `NULL`; cleanup via `goto error;`.
