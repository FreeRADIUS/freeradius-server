# Antora Documentation Style Guide

This document describes the writing style used across the Antora
reference pages, derived from the files in
`doc/antora/modules/reference/pages/unlang/`.  Future pages in this
directory tree should follow the same conventions.

The goal of these pages is _reference_ documentation: precise,
factual descriptions of syntax and behaviour.  How-to material and
narrative tutorials belong elsewhere (see `howto:` and `tutorials:`).

## Page Skeleton

Every page follows the same top-to-bottom structure.  A page can omit
later sections when there is nothing to say, but the relative order
never changes.

1. Page title with a single `=` heading.
2. `.Syntax` block in `[source,unlang]` showing the grammar.
3. `.Description` paragraph that says in two
   or three sentences what the statement does.
4. Definition list of the named grammar parts (`<name>::` items).
5. One or more `.Example` (or `.Examples`) blocks in `[source,unlang]`.
6. Further `==` sub-sections for sub-topics: edge cases, related
   keywords, performance, compatibility, etc.
7. Two-line `//` copyright footer.

The copyright footer is mandatory and reads exactly:

```
// Copyright (C) 2026 Network RADIUS SAS.  Licenced under CC-by-NC 4.0.
// This documentation was developed by Network RADIUS SAS.
```

## Headings

- Page title uses `=` and reads either `The <keyword> Statement`,
  `<Capitalized Topic>`, or a plain noun phrase (e.g. `Local
  Variables`, `Attribute References`).  Both forms appear in the
  existing pages.  Use `The <keyword> Statement` for keywords that
  introduce a block; use a noun phrase for pages that describe a
  concept rather than a single keyword.
- Section headings use `==`.  Capitalize like a sentence
  (`== Practical Suggestions`), or as a noun phrase (`== Performance
  and Data Types`).  Don't quote keywords in headings.
- Sub-sub-headings use `===`.  Use them sparingly.

## Syntax Blocks

Each page starts with one `.Syntax` block.  Pages that document
multiple distinct forms may have more than one `.Syntax` block, one
per form, placed near the prose that describes the form.

```
.Syntax
[source,unlang]
----
keyword <required> [ <optional> ] {
    [ statements ]
}
----
```

Conventions inside the syntax block:

- `<name>` (angle brackets, no quotes) marks a placeholder the user
  must fill in.
- `[ thing ]` marks an optional element.
- `[ statements ]` is the standard placeholder for the body of a
  block.
- Indentation is four spaces.
- Use lowercase keywords (`if`, `case`, `subrequest`).

## Definition Lists for Grammar Parts

After the description, each placeholder named in the syntax block
gets its own definition list entry:

```
<name>:: First sentence describing the field.
+
Continuation paragraph with more detail.
+
Further notes, constraints, or sub-cases.
```

Use the `+` continuation marker for multi-paragraph entries.  Each
entry starts with a short lead-in sentence, then expands with
constraints, default behaviour, and edge cases as needed.

Always cover, in roughly this order: what the value is, what types
or forms it can take, what happens when it is omitted (if optional),
and what causes it to be rejected.

The `[ statements ]` entry, when present, comes last and typically
reads `One or more` unlang `commands.` followed by any
block-specific notes about how the body is processed.

## Examples

- Introduce examples with `.Example` or `.Examples`.  Use a
  descriptive title when the example needs context: `.Example of
  Looping over children of a structural type`, `.Example Without
  Brackets`.
- Each example is a `[source,unlang]` block, fenced with `----`.
- Use four-space indentation inside the example.
- Keep examples small enough to fit on a screen.  Prefer two short
  examples over one long one when the topic has more than one
  important variant.
- Use realistic but obvious placeholder values: `bob` for usernames,
  `192.0.2.1` and `192.168/16` for addresses, `sql`, `ldap`,
  `detail`, `proxy` for module names.
- For pseudocode (not real unlang), use an unfenced `----` block
  with no language tag.

## Voice and Tone

- Third person, present tense: "The `if` statement evaluates a
  condition", not "We evaluate" or "You will evaluate".
- Active voice: "The server stores the value", not "The value is
  stored by the server".
- Direct and short.  Two-sentence paragraphs are common.  Avoid
  hedging language ("might possibly", "could perhaps").  State what
  happens.
- Address the reader as "you" only inside `[NOTE]` blocks or
  practical suggestions, sparingly.
- "We recommend ..." is the standard phrasing for guidance, used
  rarely: e.g. "In general, we recommend using the
  `redundant-load-balance` statement instead of `redundant`."

## Formatting Conventions

- Backticks for: keywords (`if`, `switch`), module names (`sql`,
  `ldap`), attribute names (`User-Name`), data types (`uint32`,
  `string`), operators (`:=`, `+=`), return codes (`fail`, `ok`,
  `noop`), filenames and paths (`raddb/mods-enabled/`,
  `radiusd.conf`), config section names (`recv Access-Request`).
- Underscored placeholders: `_<condition>_`, `_<rhs>_`, `_<lhs>_`,
  `_<value>_`, `_<expansion>_`.  The italic markup carries the
  "this is a grammar variable" meaning.  Don't underscore prose
  references to the same concept.
- Italics for: emphasis (`_must_`, `_only_`, `_true_`, `_false_`),
  contrasts (`_reference_ documentation`), and grammar variables in
  prose.  Bold (`*...*`) is reserved for stronger emphasis and is
  rare; the existing pages use it for "the server *will not start*"
  and similar warnings.
- Quotes: double-quoted ASCII strings (`"bob"`).  Smart quotes are
  forbidden (see the wrap script in `scripts/asciidoc/wrap.py`).
  When showing literal text in prose, prefer backticks
  (\`true\`) to quotes ("true") unless the text contains a
  backtick.
- Inline cross-references use Antora xrefs:
  `xref:unlang/foreach.adoc[foreach]`,
  `xref:type/index.adoc[data type]`.  The link text is the bare
  noun, with no surrounding backticks.

## Cross-References

Every mention of another `unlang` statement or concept is a link the
first time it appears in a page, and usually every subsequent time.
The links are dense by design: a reader landing in the middle of any
page can navigate to related material in one click.

Use the full Antora xref form: `xref:unlang/foo.adoc[foo]`.  For
cross-module references include the module name:
`xref:reference:xlat/index.adoc[dynamic expansion function]`.

When linking to a related concept under a different name, use the
descriptive name as the link text:
`xref:xlat/index.adoc[dynamic expansion]`,
`xref:unlang/condition/index.adoc[conditional expression]`.

## Admonitions

The pages use `[NOTE]` blocks bordered by `====`.  Reserve them for:

- A short caveat that interrupts the main flow ("`catch` runs on all
  rcodes, not just failures").
- A pointer to a non-obvious behaviour.
- A warning about behaviour that has changed between versions.

Don't use them as a substitute for ordinary prose.  An admonition
that is more than three or four lines should be promoted to a
sub-section.

`[WARNING]`, `[TIP]`, and similar admonition types are not currently
used in this directory; default to `[NOTE]`.

## Tables

Use AsciiDoc tables (`[options="header"]` with explicit `[cols="..."]`)
for operator and return-code references.  Two columns is the norm:
the symbol or keyword on the left, the description on the right.
A 10% / 90% column split is common.

Don't use tables as a substitute for paragraphs or definition lists.
Tables work well for "match this to that" reference material, and
poorly for narrative.

## Numbered Annotations on Code

For code samples where each line needs a callout, use the `<1>`,
`<2>`, ... convention with the descriptions immediately following
the block:

```
[source,unlang]
----
ldap {                    <1>
    fail = 1              <2>
    reject = return       <3>
}
----

<1> Call to the `ldap` module.
<2> Sets the priority of `fail` to `1`.
<3> Sets `reject` to cause an immediate exit.
```

## Comparisons to v3

Many pages have a paragraph or sub-section that contrasts the v4
behaviour with v3.  These follow a consistent pattern:

- "In previous versions of the server, ..." or "Unlike version 3, ...".
- A statement of what v3 did.
- A statement of what v4 does instead, and why the change was made.
- A sentence on backwards compatibility, when relevant
  ("It is allowed for backwards compatibility, but if used it is
  ignored.").

Don't apologize for v4's behaviour, and don't dwell on v3 mistakes.
One short paragraph is usually enough.

## Practical Suggestions

Pages occasionally have a section titled `== Practical Suggestions`
or similar, with short sub-sections of the form "Brackets are
usually optional" or "Multi-line conditions".  Each sub-section
starts with a single direct statement of the suggestion, followed
by a minimal example.  Don't pad them.

## Limits and Failures

Document what causes a statement to fail, and what return code it
produces on failure.  The standard phrasing is "returns the `fail`
rcode" or "returns `fail`".  Always link `rcode` to
`xref:unlang/return_codes.adoc[rcode]` on first use within a page.

When a statement has hard limits (maximum nesting depth, maximum
index, maximum string length, etc.), call them out explicitly with
the number.  Indexes are limited to 1000; nesting is limited only
by the interpreter stack; etc.

## What Not to Do

These patterns appear occasionally in other docs but should be
avoided in this directory:

- Marketing language ("powerful", "robust", "industry-leading").
- Em-dashes.  Use commas, colons, parentheses, or separate
  sentences.
- Long unbroken paragraphs.  If a concept takes a lot of explanation,
  it should be broken into multiple sub-concepts.
- Backticked phrases instead of italicized grammar variables.  The
  syntax block defines `_<value>_`; in prose, refer to it as
  `_<value>_`, not as ``<value>``.
- Restating the description in the example caption.  The caption
  should give context (`.Switch over IP prefixes`), not paraphrase
  the body.
- Linking to the same page (xref-to-self).  Repeat the keyword in
  backticks instead.

## Filenames and Layout

Each page is a single `.adoc` file named after the keyword or topic
(`if.adoc`, `subrequest.adoc`, `attr.adoc`).  Use lowercase, with
hyphens for multi-word names (`load-balance.adoc`,
`redundant-load-balance.adoc`).

The page index lives in `index.adoc` and the keyword catalog in
`keywords.adoc`.  Add new pages to both when introducing a new
keyword.
