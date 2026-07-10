#!/usr/bin/env python3
"""Word-wrap asciidoc files per doc/wrap.md.

Rules:
  - Paragraphs are wrapped at 80 columns, and separated by blank lines.
  - Multiple blank lines in a row are collapsed to a single blank line.
  - Trailing whitespace on every line is removed.
  - A fixed set of non-ASCII characters is converted to ASCII
    equivalents (smart quotes, en/em dashes, ellipsis, etc.).
  - Lines starting with "//" (comments) are left unchanged.
  - Section titles begin with one or more "=" or "#" followed by a
    space.  They are left unchanged, and are always followed by a
    blank line.
  - Inline block titles are lines beginning with "." and are left
    unchanged.
  - Inline code blocks delimited by lines equal to "----" are left
    unchanged (including the delimiters themselves).
  - Code blocks delimited by lines equal to "```" are treated exactly
    like "----" blocks: the contents are passed through verbatim, but
    the "```" delimiters themselves are rewritten to "----".
  - Admonition text blocks: a label line of the form "[" + one or more
    uppercase letters + "]" (e.g. "[NOTE]", "[WARNING]", "[INFO]") that
    is immediately followed by a "====" line starts a text block.  The
    block runs until the next "====".  The "====" delimiters stay on
    their own lines, and the block contents are word-wrapped as text:
    paragraphs are wrapped, and list entries ("* ", "- ", "N. ") are
    wrapped with their continuation lines aligned after the marker.
    A label containing any lowercase letter (e.g. "[source]") does not
    qualify.
  - A bare "====" (not opened by such a label) is still treated as a
    text-block delimiter on its own line, with the contents wrapped as
    normal paragraphs.
  - Lines that start with "[" (e.g. "[NOTE]", "[source,c]") are left
    unchanged on their own line.
  - Lines starting with "|" (tables) are left unchanged.
  - List entries begin with any number of "*" markers ("* ", "** ",
    "*** ", etc.), with "- ", or with a number followed by "."
    (e.g. "1.").  Each entry is wrapped on its own; continuation lines
    are indented so they align with the text after the marker.  For
    numbered entries the leading number is preserved as-is.
  - List entries containing an "xref:" macro are left unwrapped.
    Antora's nav parser requires each "* xref:..." entry to occupy a
    single line; splitting it breaks the nav tree.
  - When the filename ends with "nav.adoc", every "*" list entry
    (regardless of marker depth) is emitted verbatim, so the nav
    parser sees one entry per line.

	$Id$
"""

import argparse
import re
import sys
import textwrap

#
#  Wrap at 80 columns means leave some whitespace at the end.
#
WIDTH = 70


#
#  Non-ASCII to ASCII replacements, per doc/wrap.md.
#
ASCII_REPLACEMENTS = str.maketrans({
    "‘": "'",   # ‘  left single quotation mark
    "’": "'",   # ’  right single quotation mark
    "–": "-",   # –  en dash
    "—": "-",   # —  em dash
    " ": " ",   #    non-breaking space
    "…": ",",   # …  horizontal ellipsis
    "“": '"',   # “  left double quotation mark
    "”": '"',   # ”  right double quotation mark
    "≤": "<=",  # ≤  less-than or equal
    "≥": ">=",  # ≥  greater-than or equal
    "→": "->",  # →  rightwards arrow
})


def to_ascii(line):
    return line.translate(ASCII_REPLACEMENTS)


def wrap_paragraph(text):
    """Wrap a paragraph of plain text at WIDTH columns."""
    if not text.strip():
        return ""
    return "\n".join(textwrap.wrap(text, width=WIDTH,
                                   break_long_words=False,
                                   break_on_hyphens=False))


def wrap_list_entry(text, indent):
    """Wrap a list entry.  The first line keeps its marker ("* ", "- ",
    or "N. "); continuation lines are indented to align with the text."""
    return "\n".join(textwrap.wrap(text, width=WIDTH,
                                   subsequent_indent=" " * indent,
                                   break_long_words=False,
                                   break_on_hyphens=False))


def is_title(line):
    """Section title: one or more "=" or "#" followed by a space."""
    s = line.lstrip()
    i = 0
    if not s:
        return False
    ch = s[0]
    if ch != "=" and ch != "#":
        return False
    while i < len(s) and s[i] == ch:
        i += 1
    return i < len(s) and s[i] == " "


def is_block_title(line):
    """Inline block title: line beginning with "."."""
    return line.lstrip().startswith(".")


def is_comment(line):
    return line.lstrip().startswith("//")


_LIST_MARKER_RE = re.compile(r"^(?:\*+|-|\d+\.)\s+")


def list_marker_len(line):
    """If line begins a list entry, return the length of its marker
    including all trailing whitespace, so continuation lines line up
    with the text after the marker.  Otherwise return None."""
    m = _LIST_MARKER_RE.match(line.lstrip())
    if m:
        return m.end()
    return None


def is_list_start(line):
    return list_marker_len(line) is not None


BLOCK_DELIMS = ("----", "```")


def block_delim(line):
    """Return the matched block delimiter, or None."""
    s = line.rstrip()
    if s in BLOCK_DELIMS:
        return s
    return None


def render_delim(delim):
    """Render a block delimiter for output.  A "```" fence is rewritten
    to "----"; other delimiters are emitted unchanged.  The block's
    contents are always passed through verbatim regardless."""
    return "----" if delim == "```" else delim


def is_table(line):
    return line.lstrip().startswith("|")


def is_attribute(line):
    """Notes, warnings, source attributes, etc. e.g. "[NOTE]"."""
    return line.lstrip().startswith("[")


#
#  An admonition label is "[" + one or more uppercase letters + "]" on a
#  line by itself, e.g. "[NOTE]", "[WARNING]", "[INFO]".  When such a
#  label is immediately followed by a "====" line, the "====" opens a
#  text block whose contents are word-wrapped (see process()).  A label
#  with any lowercase letters (e.g. "[source]") does not qualify.
#
_ADMONITION_RE = re.compile(r"^\[[A-Z]+\]$")


def is_admonition_label(line):
    return _ADMONITION_RE.match(line.strip()) is not None


def is_text_block_delim(line):
    """Text block delimiter "====".  Contents are still wrapped, but the
    delimiter itself stays on its own line."""
    return line.rstrip() == "===="


def is_star_list(line):
    """List entry whose marker starts with `*`.  Antora nav files use
    these for hierarchy (`*`, `**`, `***`, ...) and each entry must
    occupy a single line."""
    return line.lstrip().startswith("*") and list_marker_len(line) is not None


def process(lines, nav_mode=False):
    out = []
    block_open = None     # delimiter string (e.g. "----" or "```") if inside a block
    buf = []
    buf_list_indent = None  # marker length if buf holds a list entry, else None
    need_blank_after_title = False
    text_block_open = False   # inside a "[LABEL]" + "====" admonition block
    pending_admonition = False  # previous line was an uppercase "[LABEL]"

    def emit_blank():
        # Collapse runs of blank lines down to one.
        if out and out[-1] == "":
            return
        out.append("")

    def flush():
        nonlocal buf, buf_list_indent
        if not buf:
            return
        text = " ".join(s.strip() for s in buf)
        if buf_list_indent is not None:
            out.append(wrap_list_entry(text, buf_list_indent))
        else:
            out.append(wrap_paragraph(text))
        buf = []
        buf_list_indent = None

    for line in lines:
        # Strip just the trailing newline; keep the rest of the line
        # exactly as-is so we can preserve block contents verbatim.
        raw = line.rstrip("\n")

        if block_open is not None:
            # Inside a "----" or "```" block, the only line we look at
            # is the matching closing delimiter.  Everything else,
            # including lines that resemble titles, lists, etc., is
            # passed through verbatim.  The closing delimiter is
            # rewritten (a "```" fence becomes "----"); the contents are
            # untouched.
            if block_delim(raw) == block_open:
                out.append(render_delim(block_open))
                block_open = None
            else:
                out.append(raw)
            continue

        # Outside any block: convert known non-ASCII characters to ASCII
        # equivalents and strip trailing whitespace.
        line = to_ascii(raw).rstrip()

        if text_block_open:
            # Inside a "[LABEL]" + "====" admonition block.  The contents
            # are text: paragraphs are word-wrapped (blank lines separate
            # paragraphs) and list entries are wrapped with their
            # continuation lines aligned after the marker, just as in the
            # normal document flow.  The block ends at the next "====",
            # which stays on its own line.
            if is_text_block_delim(line):
                flush()
                out.append(line)
                text_block_open = False
                continue
            if line == "":
                flush()
                emit_blank()
                continue
            marker_len = list_marker_len(line)
            if marker_len is not None:
                flush()
                buf = [line]
                buf_list_indent = marker_len
                continue
            # Continuation of the current paragraph or list entry.
            buf.append(line)
            continue

        # Force a blank line right after a section title.  We emit it
        # lazily so that an input already containing the blank line
        # doesn't end up with two of them.
        if need_blank_after_title and line != "":
            emit_blank()
        need_blank_after_title = False

        # An uppercase "[LABEL]" only opens a text block if the very next
        # line is "====".  Consume the pending flag here; the "===="
        # handler below reads was_pending.
        was_pending = pending_admonition
        pending_admonition = False

        delim = block_delim(line)
        if delim is not None:
            flush()
            # Rewrite the opening "```" fence to "----", but keep
            # block_open set to the delimiter we actually saw so the
            # matching closing "```" is still recognised.
            out.append(render_delim(delim))
            block_open = delim
            continue

        if is_title(line):
            flush()
            out.append(line)
            need_blank_after_title = True
            continue

        if is_text_block_delim(line):
            flush()
            out.append(line)
            # "[LABEL]" immediately followed by "====" opens a text block
            # whose contents are wrapped, until the next "====".  A bare
            # "====" is just a delimiter on its own line, as before.
            if was_pending:
                text_block_open = True
            continue

        if is_attribute(line):
            flush()
            out.append(line)
            # Remember an uppercase "[LABEL]" so the next line can decide
            # whether it opens an admonition text block.
            if is_admonition_label(line):
                pending_admonition = True
            continue

        if is_comment(line) or is_block_title(line) or is_table(line):
            flush()
            out.append(line)
            continue

        if line == "":
            flush()
            emit_blank()
            continue

        marker_len = list_marker_len(line)
        if marker_len is not None:
            flush()
            # In an Antora nav file, every "*" list entry (regardless
            # of nesting depth) must stay on a single line so the nav
            # parser can match its hierarchy.  Emit verbatim.
            if nav_mode and is_star_list(line):
                out.append(line)
                continue
            buf = [line]
            buf_list_indent = marker_len
            continue

        # Continuation of the current paragraph or list entry.
        buf.append(line)

    flush()
    if need_blank_after_title:
        emit_blank()
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Word-wrap asciidoc files.")
    ap.add_argument("files", nargs="*", help="Files to wrap (default: stdin).")
    ap.add_argument("-i", "--in-place", action="store_true",
                    help="Rewrite files in place.")
    args = ap.parse_args()

    if not args.files:
        if args.in_place:
            ap.error("--in-place requires file arguments")
        sys.stdout.write(process(sys.stdin))
        return

    for path in args.files:
        # Antora nav files (any filename ending in "nav.adoc") have
        # one-line-per-entry hierarchy expressed with "*", "**", ...
        # markers.  Wrapping a "*" entry breaks the nav parser, so
        # those entries are emitted verbatim in this mode.
        nav_mode = path.endswith("nav.adoc")
        with open(path, "r", encoding="utf-8") as f:
            wrapped = process(f, nav_mode=nav_mode)
        if args.in_place:
            with open(path, "w", encoding="utf-8") as f:
                f.write(wrapped)
        else:
            sys.stdout.write(wrapped)


if __name__ == "__main__":
    main()
