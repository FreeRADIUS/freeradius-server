#!/usr/bin/env python3
"""Format FreeRADIUS raddb/ configuration files.

Implements the rules described in scripts/asciidoc/format_raddb.md:

  * Skip files that are not FreeRADIUS configuration
    (mods-config/* except *.conf, ALL-UPPERCASE basenames,
    *.md / *.txt / *.adoc / *.rst, anything under raddb/certs).
  * Use tabs (8 chars) for indentation; never mix tabs and spaces.
  * Strip trailing whitespace.
  * Strip trailing backslashes from `if` / `elseif` lines.
  * Comment text is indented with two spaces after the `#`.
    Code inside a comment (4-space or tab indent after `#`) is
    preserved verbatim.
  * Word-wrap long comment paragraphs at 69 columns, plus 8 columns
    per indentation level beyond 3.
  * Inside comments: uppercase `NOTE:`, `TIP:`, `WARNING:`,
    `IMPORTANT:`.
  * Inside comments: strip the `raddb/` prefix from configuration
    file references.
  * Convert `# # Title`-style headings to `# = Title`-style headings.
  * Convert `# .Title` to `# = Title`.
  * Warn if a configuration item has no documentation (a preceding
    comment whose first word is `<name>::`).  Documentation found in
    any input file satisfies the check for that (parent-hierarchy,
    name) pair.

Usage:
    scripts/format_raddb.py [--in-place] [-w] [--format=NAME] PATH ...

`--format=NAME` restricts the transformations applied.  Valid names:
  headings - only convert `# # Title` and `# .Title` to `# = Title`.
  indent   - only normalize whitespace and indentation.
  wrap     - only re-wrap comment paragraphs.
If `--format` is not given, all transformations run.

PATH may be a file or a directory.  Directories are walked
recursively; ineligible files are skipped silently.
"""

import argparse
import os
import re
import sys
from pathlib import Path

TAB_WIDTH = 8
BASE_WIDTH = 70
INDENT_BONUS_DEPTH = 3
INDENT_BONUS_PER_LEVEL = 8

IGNORE_EXTENSIONS = (".md", ".txt", ".adoc", ".rst")
ADMONITIONS = ("NOTE", "TIP", "WARNING", "IMPORTANT")

_ADMONITION_RE = re.compile(
    r"\b(" + "|".join(ADMONITIONS) + r")(\s*):",
    re.IGNORECASE,
)
_COMMENT_RE = re.compile(r"^([ \t]*)(#+)(.*)$")
_DOC_HEAD_RE = re.compile(r"^\s*([A-Za-z_][\w-]*)\s*::")
_ITEM_RE = re.compile(r"^([A-Za-z_$][\w.-]*)\s*=")
_SECTION_OPEN_RE = re.compile(r"^([A-Za-z_$][\w.-]*)(?:\s+([\w.-]+))?\s*\{")

# AsciiDoc structure markers that must stay on their own line inside a
# comment.  conf2adoc treats these as block delimiters or list markers, so
# folding them into a prose paragraph silently breaks the rendered output.
_BLOCK_DELIM_RE = re.compile(r"^(====+|----+|\.\.\.\.+|\+\+\+\++|____+|"
                              r"~~~~+|\^\^\^\^+|<<<<+|\*\*\*\*+)$")
_ATTR_RE = re.compile(r"^\[.*\]$")
_LIST_RE = re.compile(r"^(?:\*+|-|\d+\.)\s+\S")
_TABLE_RE = re.compile(r"^\|")

# `.Foo` patterns that look like dot-titles but should be left alone:
#   * Reserved AsciiDoc block-title labels that we keep verbatim.
#   * A leading `."..."` quoted form, which is data not a title.
_DOT_TITLE_KEEP_RE = re.compile(
    r'^(?:"|(?:Example|Return|Default|Output)\b)'
)


# ---------------------------------------------------------------------------
#  File selection
# ---------------------------------------------------------------------------


def find_raddb_root(paths):
    """Locate the nearest ancestor named `raddb` for one of the input paths.

    Falls back to the current working directory if none is found, which is
    sufficient for the filename-only filtering rules.
    """
    for p in paths:
        rp = p.resolve()
        for parent in (rp, *rp.parents):
            if parent.name == "raddb":
                return parent
    return Path(".").resolve()


def should_format(path, raddb_root):
    """Return True if `path` should be reformatted."""
    if not path.is_file():
        return False

    try:
        rel = path.resolve().relative_to(raddb_root)
        parts = rel.parts
    except ValueError:
        parts = (path.name,)

    name = path.name

    if name.startswith("."):
        return False

    if "certs" in parts:
        return False

    if name.lower().endswith(IGNORE_EXTENSIONS):
        return False

    if "." not in name and name.isupper():
        return False

    if "mods-config" in parts and not name.endswith(".conf"):
        return False

    if name.endswith(".md") or name.endswith(".txt") or name.endswith(".mk"):
        return False

    return True


def walk_files(root):
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            yield Path(dirpath) / name


# ---------------------------------------------------------------------------
#  Line-level helpers
# ---------------------------------------------------------------------------


def visual_column(line):
    """Return the visual column reached after the line's leading whitespace."""
    col = 0
    for ch in line:
        if ch == "\t":
            col = (col // TAB_WIDTH + 1) * TAB_WIDTH
        elif ch == " ":
            col += 1
        else:
            break
    return col


def normalize_leading_whitespace(line):
    """Convert leading whitespace to as many tabs as possible, then spaces."""
    i = 0
    col = 0
    while i < len(line) and line[i] in (" ", "\t"):
        if line[i] == "\t":
            col = (col // TAB_WIDTH + 1) * TAB_WIDTH
        else:
            col += 1
        i += 1
    rest = line[i:]
    tabs = col // TAB_WIDTH
    spaces = col % TAB_WIDTH
    return "\t" * tabs + " " * spaces + rest


def strip_if_continuation(line):
    """Remove a trailing backslash from an `if` or `elseif` line."""
    stripped = line.lstrip()
    first = stripped.split(None, 1)[0] if stripped else ""
    if first not in ("if", "elseif"):
        return line
    if line.endswith("\\"):
        return line[:-1].rstrip()
    return line


def upper_admonitions(text):
    return _ADMONITION_RE.sub(lambda m: m.group(1).upper() + ":", text)


def strip_raddb_prefix(text):
    text = re.sub(r"`raddb/([^`]+)`", r"`\1`", text)
    text = re.sub(r"(?<![\w./])raddb/([\w./-]+)", r"\1", text)
    return text


def wrap_width_for_depth(depth):
    if depth <= INDENT_BONUS_DEPTH:
        return BASE_WIDTH
    return BASE_WIDTH + (depth - INDENT_BONUS_DEPTH) * INDENT_BONUS_PER_LEVEL


def wrap_paragraph(words, prefix, width):
    if not words:
        return []
    lines = []
    cur = words[0]
    for w in words[1:]:
        if len(prefix) + len(cur) + 1 + len(w) > width:
            lines.append(prefix + cur)
            cur = w
        else:
            cur += " " + w
    lines.append(prefix + cur)
    return lines


# ---------------------------------------------------------------------------
#  Comment-block formatting
# ---------------------------------------------------------------------------


def comment_match(line):
    return _COMMENT_RE.match(line)


def is_comment(line):
    return comment_match(line) is not None


def format_comment_block(block):
    """Format a contiguous run of comment lines.

    Input lines have no trailing newline; output lines do not either.
    """
    if not block:
        return []

    norm = [normalize_leading_whitespace(l.rstrip()) for l in block]

    # Find indent + depth from the first *normal* (single-hash) line.  A
    # decorative line like `#######` is preserved verbatim and does not
    # contribute its hash count to the rest of the block.
    block_indent = None
    depth = 0
    for line in norm:
        m = comment_match(line)
        if not m:
            continue
        indent, hashes, rest = m.groups()
        if len(hashes) == 1:
            block_indent = indent
            depth = visual_column(line) // TAB_WIDTH
            break
    if block_indent is None:
        # Block contains only decorative/multi-hash lines - emit verbatim.
        return list(norm)

    width = wrap_width_for_depth(depth)
    text_prefix = block_indent + "#  "
    bare_prefix = block_indent + "#"

    out = []
    paragraph = []
    in_fence = False

    def flush_paragraph():
        if paragraph:
            out.extend(wrap_paragraph(paragraph, text_prefix, width))
            paragraph.clear()

    for raw, line in zip(block, norm):
        m = comment_match(line)
        if not m:
            flush_paragraph()
            out.append(line)
            continue
        indent, hashes, rest = m.groups()

        # Inside a fenced ``` ... ``` block: emit the original line
        # verbatim and only watch for the closing fence.  No wrapping,
        # heading conversion, indent fix-ups, or content rewriting.
        if in_fence:
            flush_paragraph()
            out.append(line)
            if rest.rstrip().endswith("```"):
                in_fence = False
            continue

        # Opening fence: the comment body starts with ```.  Emit the line
        # verbatim and enter fenced mode (unless the same line also closes
        # the fence with a trailing ```).
        text_after_hash = rest.lstrip()
        if text_after_hash.startswith("```"):
            flush_paragraph()
            out.append(line)
            remainder = text_after_hash[3:].rstrip()
            if not (remainder and remainder.endswith("```")):
                in_fence = True
            continue

        # Two or more leading `#`s mark either a decorative separator
        # (#####...) or a commented-out code block (##  some code).  In
        # both cases the content is not prose and must be preserved
        # verbatim: no wrap, no heading conversion, no indent rewrite.
        # Emit the original line so the leading whitespace is preserved
        # exactly as written.
        if len(hashes) > 1:
            flush_paragraph()
            out.append(raw.rstrip())
            continue

        if rest == "":
            flush_paragraph()
            out.append(bare_prefix)
            continue

        # Commented-out configuration item: `#` is already at column 0 and
        # the content after it looks like `name = value`.  Preserve the line
        # verbatim so the `#` stays at column 0 even when the surrounding
        # section is indented.
        body = rest.lstrip()
        if indent == "" and _ITEM_RE.match(body):
            flush_paragraph()
            out.append(line)
            continue

        # Code line embedded in the comment: tab or 4+ leading spaces.
        if rest.startswith("\t") or rest[:4] == "    ":
            flush_paragraph()
            out.append(bare_prefix + rest.rstrip())
            continue

        text = rest.lstrip()
        gap = rest[: len(rest) - len(text)]
        has_tab_gap = "\t" in gap

        # `# = Title` already in asciidoc form - emit verbatim, with the
        # standard two-space gap.
        if re.match(r"^=+\s+\S", text):
            flush_paragraph()
            out.append(text_prefix + text)
            continue

        # `# # Title` -> `# = Title` (one `=` per `#`).  If tabs sit
        # between the outer and inner `#`, the line is a commented-out
        # comment, not a title; preserve it verbatim.
        hm = re.match(r"^(#+)\s+(\S.*)$", text)
        if hm:
            flush_paragraph()
            if has_tab_gap:
                out.append(line)
            else:
                equals = "=" * len(hm.group(1))
                out.append(text_prefix + equals + " " + hm.group(2))
            continue

        # `# .Title` -> `# = Title`.  Only a single leading dot followed by
        # non-dot, non-whitespace text counts as a title.  Multiple dots
        # (e.g. `..foo`, `...`) are prose or AsciiDoc structure, not titles.
        # A tab in the gap likewise means a commented-out marker, not a
        # heading.
        dm = re.match(r"^\.([^.\s].*)$", text)
        if dm:
            flush_paragraph()
            if has_tab_gap or _DOT_TITLE_KEEP_RE.match(dm.group(1)):
                out.append(line)
            else:
                out.append(text_prefix + "= " + dm.group(1))
            continue

        # AsciiDoc structure markers - keep on their own line, do not wrap.
        if (_BLOCK_DELIM_RE.match(text) or _ATTR_RE.match(text)
                or _LIST_RE.match(text) or _TABLE_RE.match(text)):
            flush_paragraph()
            text = upper_admonitions(text)
            text = strip_raddb_prefix(text)
            out.append(text_prefix + text)
            continue

        # Plain text - apply text fixes, then accumulate for wrapping.
        text = upper_admonitions(text)
        text = strip_raddb_prefix(text)
        paragraph.extend(text.split())

    flush_paragraph()
    return out


# ---------------------------------------------------------------------------
#  Whole-file formatting
# ---------------------------------------------------------------------------


def format_code_line(line):
    line = line.rstrip()
    line = normalize_leading_whitespace(line)
    line = strip_if_continuation(line)
    return line


def format_file_text(text, mode=None):
    """Apply formatting to `text`.

    `mode` selects which transformations are applied:
      * None       - all transformations (the default behavior).
      * 'indent'   - only whitespace / indentation normalization.
      * 'headings' - only heading conversion in comments.
      * 'wrap'     - only re-wrap comment paragraphs.
    """
    if mode is None:
        return _format_full(text)
    if mode == "indent":
        return _format_indent_only(text)
    if mode == "headings":
        return _format_headings_only(text)
    if mode == "wrap":
        return _format_wrap_only(text)
    raise ValueError(f"unknown format mode: {mode!r}")


def _format_full(text):
    src = text.splitlines()
    out = []
    i = 0
    while i < len(src):
        if is_comment(src[i]):
            j = i
            while j < len(src) and is_comment(src[j]):
                j += 1
            out.extend(format_comment_block(src[i:j]))
            i = j
        else:
            out.append(format_code_line(src[i]))
            i += 1
    result = "\n".join(out)
    if text.endswith("\n"):
        result += "\n"
    return result


def _format_indent_only(text):
    """Normalize whitespace only.  Comment content (text, headings, wrap)
    is left untouched."""
    out = []
    in_fence = False
    for raw in text.splitlines():
        m = comment_match(raw)
        if m:
            indent, hashes, rest = m.groups()
            # Inside a fenced ``` ... ``` block: preserve raw text.
            if in_fence:
                out.append(raw)
                if rest.rstrip().endswith("```"):
                    in_fence = False
                continue
            text_after_hash = rest.lstrip()
            if text_after_hash.startswith("```"):
                out.append(raw)
                remainder = text_after_hash[3:].rstrip()
                if not (remainder and remainder.endswith("```")):
                    in_fence = True
                continue

            line = raw.rstrip()
            indent, hashes, rest = comment_match(line).groups()
            # `##`-prefixed lines are commented-out code blocks (or
            # decorative separators); leave them entirely alone.
            if len(hashes) > 1:
                out.append(line)
                continue
            body = rest.lstrip()
            # Commented-out config item: `#` stays at column 0.
            if indent == "" and _ITEM_RE.match(body):
                out.append(line)
                continue
            out.append(normalize_leading_whitespace(indent) + hashes + rest)
        else:
            in_fence = False
            line = raw.rstrip()
            line = normalize_leading_whitespace(line)
            line = strip_if_continuation(line)
            out.append(line)
    result = "\n".join(out)
    if text.endswith("\n"):
        result += "\n"
    return result


def _format_headings_only(text):
    """Convert `# # Title` and `# .Title` patterns to `# = Title`.  Leave
    indentation and comment text otherwise untouched."""
    out = []
    in_fence = False
    for line in text.splitlines():
        m = comment_match(line)
        if not m:
            in_fence = False
            out.append(line)
            continue
        indent, hashes, rest = m.groups()
        # Inside a fenced ``` ... ``` block: emit verbatim, look for close.
        if in_fence:
            out.append(line)
            if rest.rstrip().endswith("```"):
                in_fence = False
            continue
        # Opening fence: emit verbatim and enter fenced mode.
        text_after_hash = rest.lstrip()
        if text_after_hash.startswith("```"):
            out.append(line)
            remainder = text_after_hash[3:].rstrip()
            if not (remainder and remainder.endswith("```")):
                in_fence = True
            continue
        # Decorative multi-hash lines: leave alone.
        if len(hashes) > 1:
            out.append(line)
            continue
        if rest == "":
            out.append(line)
            continue
        # Preserve the whitespace between `#` and the text.
        text_part = rest.lstrip()
        gap = rest[: len(rest) - len(text_part)]
        # A tab in the gap means the inner `#` (or `.`) was a comment
        # marker that has itself been commented out, not a heading marker.
        # Preserve such lines verbatim.
        if "\t" in gap:
            out.append(line)
            continue

        hm = re.match(r"^(#+)\s+(\S.*)$", text_part)
        if hm:
            equals = "=" * len(hm.group(1))
            out.append(indent + hashes + gap + equals + " " + hm.group(2))
            continue

        # `.Title` headings are not rewritten in --format=headings mode.
        # Dot-titles are valid AsciiDoc on their own; the headings pass
        # only handles the `#`-prefixed style.
        out.append(line)
    result = "\n".join(out)
    if text.endswith("\n"):
        result += "\n"
    return result


def _format_wrap_only(text):
    """Word-wrap comment paragraphs.  Indentation, headings, structure
    markers, and comment content are otherwise left untouched."""
    src = text.splitlines()
    out = []
    i = 0
    while i < len(src):
        if is_comment(src[i]):
            j = i
            while j < len(src) and is_comment(src[j]):
                j += 1
            out.extend(_wrap_comment_block(src[i:j]))
            i = j
        else:
            out.append(src[i])
            i += 1
    result = "\n".join(out)
    if text.endswith("\n"):
        result += "\n"
    return result


def _wrap_comment_block(block):
    if not block:
        return []

    # Use the first single-hash line to pin the wrap prefix.
    block_indent = None
    depth = 0
    for line in block:
        m = comment_match(line)
        if m and len(m.group(2)) == 1:
            block_indent = m.group(1)
            depth = visual_column(line) // TAB_WIDTH
            break
    if block_indent is None:
        return list(block)

    width = wrap_width_for_depth(depth)
    text_prefix = block_indent + "#  "

    out = []
    paragraph = []
    in_fence = False

    def flush_paragraph():
        if paragraph:
            out.extend(wrap_paragraph(paragraph, text_prefix, width))
            paragraph.clear()

    for line in block:
        m = comment_match(line)
        if not m:
            flush_paragraph()
            out.append(line)
            continue
        indent, hashes, rest = m.groups()

        if in_fence:
            flush_paragraph()
            out.append(line)
            if rest.rstrip().endswith("```"):
                in_fence = False
            continue
        text_after_hash = rest.lstrip()
        if text_after_hash.startswith("```"):
            flush_paragraph()
            out.append(line)
            remainder = text_after_hash[3:].rstrip()
            if not (remainder and remainder.endswith("```")):
                in_fence = True
            continue

        # Decorative, bare `#`, code, or any heading / structure marker
        # is preserved verbatim - only prose is wrapped.
        if len(hashes) > 1 or rest == "":
            flush_paragraph()
            out.append(line)
            continue
        if rest.startswith("\t") or rest[:4] == "    ":
            flush_paragraph()
            out.append(line)
            continue
        body = rest.lstrip()
        if indent == "" and _ITEM_RE.match(body):
            flush_paragraph()
            out.append(line)
            continue
        text = body
        if (re.match(r"^=+\s+\S", text)
                or re.match(r"^#+\s+\S", text)
                or re.match(r"^\.([^.\s].*)$", text)):
            flush_paragraph()
            out.append(line)
            continue
        if (_BLOCK_DELIM_RE.match(text) or _ATTR_RE.match(text)
                or _LIST_RE.match(text) or _TABLE_RE.match(text)):
            flush_paragraph()
            out.append(line)
            continue

        paragraph.extend(text.split())

    flush_paragraph()
    return out


# ---------------------------------------------------------------------------
#  Documentation cross-correlation
# ---------------------------------------------------------------------------


def collect_documented_items(lines):
    """Return ((parent_path, name) set, bare-name set) for one file.

    A doc block is any preceding `#` comment whose first text line begins
    with `<name>::`.  `parent_path` is a tuple of enclosing section names.

    The first set keys on (parent_path, name) for cross-file
    deduplication.  The second set holds bare names, used to suppress
    warnings for same-name items elsewhere in the same file regardless of
    their parent hierarchy.
    """
    documented = set()
    documented_names = set()
    pending_doc = None  # the `name` from the most recent `name::` text line
    stack = []          # parent section names

    for raw in lines:
        line = raw.rstrip()
        stripped = line.lstrip()

        if stripped.startswith("#"):
            cm = comment_match(line)
            if cm:
                rest = cm.group(3).lstrip()
                doc = _DOC_HEAD_RE.match(rest)
                if doc:
                    pending_doc = doc.group(1)
            continue

        if stripped == "":
            # Blank lines do not break the doc-to-item association in raddb
            # style, but a comment block typically butts directly against the
            # item.  Reset on a blank to avoid spurious matches across gaps.
            pending_doc = None
            continue

        # Close braces unwind the section stack.
        if stripped.startswith("}"):
            if stack:
                stack.pop()
            pending_doc = None
            continue

        # Section open: `name [name2] {`.
        sm = _SECTION_OPEN_RE.match(stripped)
        if sm:
            name = sm.group(1)
            if pending_doc == name:
                documented.add((tuple(stack), name))
                documented_names.add(name)
            stack.append(name)
            pending_doc = None
            continue

        # Configuration item: `name = value` (also handles `#\tname = value`
        # commented-out items via the comment path above).
        im = _ITEM_RE.match(stripped)
        if im:
            name = im.group(1)
            if pending_doc == name:
                documented.add((tuple(stack), name))
                documented_names.add(name)
            pending_doc = None
            continue

        pending_doc = None

    return documented, documented_names


def check_undocumented(path, lines, documented, file_doc_names, warnings):
    """Emit warnings to `warnings` for items in `lines` lacking documentation.

    `documented` is the global set of (parent_hierarchy, name) pairs that
    are documented somewhere in the input set.  `file_doc_names` is the
    set of bare names that are documented anywhere in this same file; a
    name in that set is treated as documented regardless of the parent
    hierarchy at its occurrence.
    """
    pending_doc = None
    stack = []

    for lineno, raw in enumerate(lines, start=1):
        line = raw.rstrip()
        stripped = line.lstrip()

        if stripped.startswith("#"):
            cm = comment_match(line)
            if cm:
                rest = cm.group(3).lstrip()
                doc = _DOC_HEAD_RE.match(rest)
                if doc:
                    pending_doc = doc.group(1)
            continue

        if stripped == "":
            pending_doc = None
            continue

        if stripped.startswith("}"):
            if stack:
                stack.pop()
            pending_doc = None
            continue

        sm = _SECTION_OPEN_RE.match(stripped)
        if sm:
            name = sm.group(1)
            key = (tuple(stack), name)
            if (pending_doc != name
                    and key not in documented
                    and name not in file_doc_names):
                warnings.append(
                    f"{path}:{lineno}: warning: section '{name}' has no documentation"
                )
            stack.append(name)
            pending_doc = None
            continue

        im = _ITEM_RE.match(stripped)
        if im:
            name = im.group(1)
            key = (tuple(stack), name)
            if (pending_doc != name
                    and key not in documented
                    and name not in file_doc_names):
                warnings.append(
                    f"{path}:{lineno}: warning: item '{name}' has no documentation"
                )
            pending_doc = None
            continue

        pending_doc = None


# ---------------------------------------------------------------------------
#  Driver
# ---------------------------------------------------------------------------


def collect_input_files(paths, raddb_root):
    files = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for fp in walk_files(path):
                if should_format(fp, raddb_root):
                    files.append(fp)
        else:
            if should_format(path, raddb_root):
                files.append(path)
    return files


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Format FreeRADIUS raddb/ configuration files.",
    )
    ap.add_argument("paths", nargs="+", help="Files or directories to format.")
    ap.add_argument("-i", "--in-place", action="store_true",
                    help="Rewrite files in place instead of printing to stdout.")
    ap.add_argument("-w", "--warn", action="store_true",
                    help="Print warnings about undocumented items and sections.")
    ap.add_argument("--format", choices=("headings", "indent", "wrap"),
                    default=None,
                    help="Run only the named formatting pass.  If unset, all "
                         "passes run.")
    args = ap.parse_args(argv)

    input_paths = [Path(p) for p in args.paths]
    raddb_root = find_raddb_root(input_paths)
    files = collect_input_files(input_paths, raddb_root)

    if not files:
        print("format_raddb: no input files matched the formatting rules",
              file=sys.stderr)
        return 1

    # Read all sources first so the doc-check pass can cross-correlate.
    sources = {}
    for fp in files:
        try:
            sources[fp] = fp.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            print(f"format_raddb: {fp}: {e}", file=sys.stderr)
            sources[fp] = None

    documented = set()
    per_file_doc_names = {}
    if args.warn:
        for fp, text in sources.items():
            if text is None:
                continue
            file_docs, file_names = collect_documented_items(text.splitlines())
            documented |= file_docs
            per_file_doc_names[fp] = file_names

    warnings = []
    exit_code = 0

    for fp in files:
        text = sources[fp]
        if text is None:
            exit_code = 1
            continue

        if args.warn:
            check_undocumented(fp, text.splitlines(), documented,
                               per_file_doc_names.get(fp, set()), warnings)

        formatted = format_file_text(text, mode=args.format)

        if args.in_place:
            if formatted != text:
                try:
                    fp.write_text(formatted, encoding="utf-8")
                except OSError as e:
                    print(f"format_raddb: {fp}: {e}", file=sys.stderr)
                    exit_code = 1
        else:
            sys.stdout.write(formatted)

    if args.warn:
        for w in warnings:
            print(w, file=sys.stderr)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
