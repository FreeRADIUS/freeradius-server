#!/usr/bin/env python3
"""Word-wrap asciidoc files per doc/wrap.md.

Rules:
  - Paragraphs are wrapped at 80 columns, and separated by blank lines.
  - Multiple blank lines in a row are collapsed to a single blank line.
  - Trailing whitespace on every line is removed.
  - Lines starting with "//" (comments) are left unchanged.
  - Section titles begin with one or more "=" or "#" followed by a
    space.  They are left unchanged, and are always followed by a
    blank line.
  - Inline block titles are lines beginning with "." and are left
    unchanged.
  - Inline blocks delimited by lines equal to "----" are left unchanged
    (including the delimiters themselves).
  - Code blocks delimited by lines equal to "```" are also left
    unchanged, and follow the same rules as "----" blocks.
  - Lines starting with "|" (tables) are left unchanged.
  - List entries begin with "* " or "- ".  Each entry is wrapped on its
    own; continuation lines are indented 2 spaces so they align with
    the text after the bullet marker.

	$Id$
"""

import argparse
import sys
import textwrap

#
#  Wrap at 80 columns means leave some whitespace at the end.
#
WIDTH = 70


def wrap_paragraph(text):
    """Wrap a paragraph of plain text at WIDTH columns."""
    if not text.strip():
        return ""
    return "\n".join(textwrap.wrap(text, width=WIDTH,
                                   break_long_words=False,
                                   break_on_hyphens=False))


def wrap_list_entry(text):
    """Wrap a list entry.  The first line keeps its "* " or "- " marker;
    continuation lines are indented 2 spaces to align with the text."""
    return "\n".join(textwrap.wrap(text, width=WIDTH,
                                   subsequent_indent="  ",
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


def is_list_start(line):
    s = line.lstrip()
    return s.startswith("* ") or s.startswith("- ")


BLOCK_DELIMS = ("----", "```")


def block_delim(line):
    """Return the matched block delimiter, or None."""
    s = line.rstrip()
    if s in BLOCK_DELIMS:
        return s
    return None


def is_table(line):
    return line.lstrip().startswith("|")


def process(lines):
    out = []
    block_open = None     # delimiter string (e.g. "----" or "```") if inside a block
    buf = []
    buf_is_list = False
    need_blank_after_title = False

    def emit_blank():
        # Collapse runs of blank lines down to one.
        if out and out[-1] == "":
            return
        out.append("")

    def flush():
        nonlocal buf, buf_is_list
        if not buf:
            return
        text = " ".join(s.strip() for s in buf)
        if buf_is_list:
            out.append(wrap_list_entry(text))
        else:
            out.append(wrap_paragraph(text))
        buf = []
        buf_is_list = False

    for line in lines:
        # Strip trailing whitespace (including the newline) from every line.
        line = line.rstrip()

        if block_open is not None:
            out.append(line)
            if block_delim(line) == block_open:
                block_open = None
            continue

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

        if is_comment(line) or is_block_title(line) or is_table(line):
            flush()
            out.append(line)
            continue

        if line == "":
            flush()
            emit_blank()
            continue

        if is_list_start(line):
            flush()
            buf = [line]
            buf_is_list = True
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
