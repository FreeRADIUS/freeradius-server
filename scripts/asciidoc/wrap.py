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
  - Code blocks delimited by lines equal to "```" are also left
    unchanged, and follow the same rules as "----" blocks.
  - Text blocks are delimited by lines equal to "====".  The "===="
    delimiters stay on their own line; the contents are still wrapped
    as normal paragraphs.
  - Lines that start with "[" (e.g. "[NOTE]", "[source,c]") are left
    unchanged on their own line.
  - Lines starting with "|" (tables) are left unchanged.
  - List entries begin with one to four "*" markers ("* ", "** ",
    "*** ", "**** "), with "- ", or with a number followed by "."
    (e.g. "1.").  Each entry is wrapped on its own; continuation lines
    are indented so they align with the text after the marker.  For
    numbered entries the leading number is preserved as-is.

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


_LIST_MARKER_RE = re.compile(r"^(?:\*{1,4}|-|\d+\.)\s+")


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


def is_table(line):
    return line.lstrip().startswith("|")


def is_attribute(line):
    """Notes, warnings, source attributes, etc. e.g. "[NOTE]"."""
    return line.lstrip().startswith("[")


def is_text_block_delim(line):
    """Text block delimiter "====".  Contents are still wrapped, but the
    delimiter itself stays on its own line."""
    return line.rstrip() == "===="


def process(lines):
    out = []
    block_open = None     # delimiter string (e.g. "----" or "```") if inside a block
    buf = []
    buf_list_indent = None  # marker length if buf holds a list entry, else None
    need_blank_after_title = False

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
            # passed through verbatim.
            out.append(raw)
            if block_delim(raw) == block_open:
                block_open = None
            continue

        # Outside any block: convert known non-ASCII characters to ASCII
        # equivalents and strip trailing whitespace.
        line = to_ascii(raw).rstrip()

        # Force a blank line right after a section title.  We emit it
        # lazily so that an input already containing the blank line
        # doesn't end up with two of them.
        if need_blank_after_title and line != "":
            emit_blank()
        need_blank_after_title = False

        delim = block_delim(line)
        if delim is not None:
            flush()
            out.append(line)
            block_open = delim
            continue

        if is_title(line):
            flush()
            out.append(line)
            need_blank_after_title = True
            continue

        if (is_comment(line) or is_block_title(line) or is_table(line)
                or is_attribute(line) or is_text_block_delim(line)):
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
        with open(path, "r", encoding="utf-8") as f:
            wrapped = process(f)
        if args.in_place:
            with open(path, "w", encoding="utf-8") as f:
                f.write(wrapped)
        else:
            sys.stdout.write(wrapped)


if __name__ == "__main__":
    main()
