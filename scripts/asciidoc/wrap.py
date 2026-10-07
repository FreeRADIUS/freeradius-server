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
  - Block delimiters are four or more of the same character, and a
    block is closed only by a line identical to the opening delimiter
    of the block.  A longer delimiter (e.g. "--------" or "========")
    is rewritten to four characters, unless the block contains a
    nested delimiter of the same character.  Shortening the outer
    delimiter would let the nested delimiter close the block early.
  - The contents of code blocks delimited by lines of "----" are left
    unchanged.
  - Code blocks delimited by lines equal to "```" are treated exactly
    like "----" blocks: the contents are passed through verbatim, but
    the "```" delimiters themselves are rewritten to "----".  As with
    a long "-" delimiter, a "```" block containing a nested "-"
    delimiter keeps its "```" delimiters.
  - A code block opened by "```" followed by a language or other text
    (e.g. "```text", "```bash") is closed only by a line equal to "```".
    The contents are passed through verbatim, and both delimiters are
    left unchanged.
  - Literal blocks are delimited by lines of four or more ".".  A
    literal block is closed only by a line identical to the opening
    delimiter.  The contents are passed through verbatim.  A longer
    delimiter is rewritten to "....", as for "-" delimiters.  A "."
    delimiter line is not a block title.
  - Verbatim blocks (delimited by four or more "-" or ".", by "```",
    or by "```" followed by text) inside admonition text blocks
    ("[LABEL]" followed by a "====" block) are treated exactly as
    outside admonition text blocks.  The block contents are passed
    through verbatim, and the delimiters are rewritten or left
    unchanged by the rule above for each delimiter.
  - Indented blocks are left unchanged, including the indent.  An
    indented block starts at a line indented by one or more spaces or
    tabs, when no paragraph or list entry is in progress.  The
    indented block runs until a blank line followed by a line that is
    not indented, or until a block delimiter or title.  Blank lines
    inside the block are kept, and blank lines at the end of the block
    collapse to one.  An indented line inside a paragraph or list
    entry is a continuation line, and is wrapped.
  - A one-line paragraph underlined with five or more "-" (within two
    characters of the text length) is a two-line section title.  The
    title is rewritten as "== Title".
  - Admonition text blocks: a label line of the form "[" + one or more
    uppercase letters + "]" (e.g. "[NOTE]", "[WARNING]", "[INFO]") that
    is immediately followed by a "====" line starts a text block.  The
    block runs until the "=" line identical to the opening delimiter.
    The "====" delimiters stay on their own lines, and the block
    contents are word-wrapped as text:
    paragraphs are wrapped, and list entries ("* ", "- ", "N. ") are
    wrapped with their continuation lines aligned after the marker.
    Lines that are left unchanged on their own line outside the block
    ("[" lines, comments, block titles, table rows, attribute entries,
    block macros, and "+") are also left unchanged inside the block.
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
  - Description list entries begin with a term followed by "::",
    ":::", "::::", or ";;", and then whitespace or the end of the line
    (e.g. "name:: The name").  Each entry is wrapped on its own, and
    the term is never split.  Continuation lines start in the first
    column.  A line holding only a term and its delimiter (e.g.
    "name::") is left unchanged.  A line beginning with a term inside a
    paragraph is a continuation line, not a new entry.  Directly after
    a list entry, the same line starts a new entry.  A term beginning
    with "[" (e.g. "[ statements ]::") is a description list entry, not
    a "[" line left unchanged.
  - List entries containing an "xref:" macro are left unwrapped.
    Antora's nav parser requires each "* xref:..." entry to occupy a
    single line; splitting it breaks the nav tree.
  - When the filename ends with "nav.adoc", every "*" list entry
    (regardless of marker depth) is emitted verbatim, so the nav
    parser sees one entry per line.
  - Lines containing a single '+' are left alone; they are used to join
    different Asciidoc blocks together.
  - The document header is left unchanged.  The header exists when
    the first line that is neither blank nor a comment is a document
    title ("= " followed by text).  The header runs from the title to
    the next blank line.  The author, revision, and attribute entry
    lines must stay directly after the title.  The lines after the
    title belong to the header only if one of the lines is an
    attribute entry.  At most two lines (author and revision) may come
    before the first attribute entry, and only attribute entries and
    comments may follow the first attribute entry.  Otherwise, the
    title is followed by a blank line, like any other section title.
  - Attribute entries (":name: value", ":name:", ":name!:", ":!name:")
    are left unchanged on their own line.
  - Block macros (e.g. "include::file.adoc[]", "image::foo.png[]",
    "ifdef::attr[]", "endif::[]") are left unchanged on their own
    line.  A block macro is a lowercase name, "::", a target (possibly
    empty) with no whitespace, and "[...]" ending the line.

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


def wrap_list_entry(text, indent, hang=True):
    """Wrap a list entry.  The first line keeps the marker ("* ", "- ",
    "N. ", or "term:: "), and the marker is never split.  If `hang` is
    True, continuation lines are indented to align with the text after
    the marker.  Otherwise, continuation lines start in the first
    column."""
    marker = text[:indent]
    body = text.expandtabs()[len(marker.expandtabs()):]
    if not body:
        return marker.rstrip()
    return "\n".join(textwrap.wrap(body, width=WIDTH,
                                   initial_indent=marker,
                                   subsequent_indent=" " * indent if hang
                                   else "",
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


_ATTRIBUTE_ENTRY_RE = re.compile(r"^:!?[^:\s][^:]*:(?:\s|$)")


def is_attribute_entry(line):
    """Attribute entry, e.g. ":doctype: manpage" or ":name!:"."""
    return _ATTRIBUTE_ENTRY_RE.match(line) is not None


_BLOCK_MACRO_RE = re.compile(r"^[a-z][a-z0-9_-]*::\S*\[.*\]$")


def is_block_macro(line):
    """Block macro, e.g. "include::file.adoc[]" or "endif::[]"."""
    return _BLOCK_MACRO_RE.match(line) is not None


def header_end(lines):
    """Return the index of the first line after the document header, or
    0 if there is no header.  The header starts at a document title
    ("= Title") that is the first line neither blank nor a comment.
    The header runs until the next blank line.

    The lines after the title belong to the header only if one of the
    lines is an attribute entry.  At most two lines (the author and
    revision lines) may come before the first attribute entry, and only
    attribute entries and comments may follow the first attribute entry.
    Otherwise, e.g. when a paragraph or "== Section" directly follows
    the title, the title is treated like any other title, and a blank
    line is added after the title."""
    for i, line in enumerate(lines):
        s = line.strip()
        if s == "" or is_comment(s):
            continue
        if not (s.startswith("= ") and s[2:].strip()):
            return 0
        end = len(lines)
        for j in range(i + 1, len(lines)):
            if lines[j].strip() == "":
                end = j
                break
        body = [b.strip() for b in lines[i + 1:end]]
        first = next((k for k, b in enumerate(body)
                      if is_attribute_entry(b)), None)
        if first is None or first > 2:
            return 0
        if not all(is_attribute_entry(b) or is_comment(b)
                   for b in body[first:]):
            return 0
        return end
    return 0


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


#
#  A description list marker is a term that does not start with
#  whitespace, followed by "::", ":::", "::::", or ";;", and then
#  whitespace or the end of the line.  The term does not end in ":" or
#  ";", so that a run of five or more ":" never matches.
#
_DLIST_MARKER_RE = re.compile(r"^\S(?:.*?[^:;])?(?:::::|:::|::|;;)(?:\s+|$)")


def dlist_marker_len(line):
    """If line begins a description list entry ("term:: definition"),
    return the length of the term, the delimiter, and any whitespace
    after the delimiter.  Otherwise return None.  Return None for a
    comment, a block title, a table row, or a list entry, even when the
    line matches the marker pattern."""
    if (is_comment(line) or is_block_title(line) or is_table(line)
            or is_list_start(line)):
        return None
    m = _DLIST_MARKER_RE.match(line)
    if m:
        return m.end()
    return None


#
#  Asciidoc delimiters are four or more of the same character, and the
#  closing delimiter must be identical to the opening delimiter.
#
_DASH_DELIM_RE = re.compile(r"-{4,}")
_EQUALS_DELIM_RE = re.compile(r"={4,}")


_FENCE_INFO_RE = re.compile(r"```[^`]+")
_DOT_DELIM_RE = re.compile(r"\.{4,}")


def block_delim(line):
    """Return the closing delimiter if line opens a verbatim block.  For
    "```", four or more "-", or four or more ".", the closing delimiter
    is line minus trailing whitespace.  For "```" followed by a language
    or other text (e.g. "```text"), the closing delimiter is "```".  If
    line does not open a verbatim block, return None."""
    s = line.rstrip()
    if (s == "```" or _DASH_DELIM_RE.fullmatch(s)
            or _DOT_DELIM_RE.fullmatch(s)):
        return s
    if _FENCE_INFO_RE.fullmatch(s):
        return "```"
    return None


def delim_render(lines, i, delim, short, nested_re):
    """Render the opening delimiter at lines[i] for output.

    The delimiter is shortened to `short` ("----" or "====") unless the
    block contains a nested delimiter matching `nested_re`.  Shortening
    the outer delimiter would let the nested delimiter close the block
    early.  An unclosed block runs to the end of the file."""
    for j in range(i + 1, len(lines)):
        s = lines[j].rstrip()
        if s == delim:
            break
        if nested_re.fullmatch(s):
            return delim
    return short


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
    """Text block delimiter, four or more "=".  The block contents are
    wrapped, and the delimiter stays on a line by itself."""
    return _EQUALS_DELIM_RE.fullmatch(line.rstrip()) is not None


def setext_title(buf, buf_list_indent, line):
    """A one-line paragraph underlined with five or more "-" is a
    two-line section title.  Return the title rewritten as "== Title",
    or None.  A list entry is never a title.  Exactly "----" is always
    a verbatim block delimiter, and the underline must be within two
    characters of the title length."""
    if len(buf) != 1 or buf_list_indent is not None:
        return None
    s = line.rstrip()
    title = buf[0].strip()
    if len(s) < 5 or not _DASH_DELIM_RE.fullmatch(s):
        return None
    if abs(len(s) - len(title)) > 2:
        return None
    return "== " + title


def is_indented(line):
    """Line starts with a space or tab, and is not blank."""
    return line[:1] in (" ", "\t") and line.strip() != ""


def is_star_list(line):
    """List entry whose marker starts with `*`.  Antora nav files use
    these for hierarchy (`*`, `**`, `***`, ...) and each entry must
    occupy a single line."""
    return line.lstrip().startswith("*") and list_marker_len(line) is not None


def process(lines, nav_mode=False):
    lines = list(lines)   # a list, so delim_render() can look ahead
    out = []
    block_open = None     # delimiter string (e.g. "----" or "```") if inside a block
    block_render = None   # delimiter written for block_open, e.g. "----"
    buf = []
    buf_list_indent = None  # marker length if buf holds a list entry, else None
    buf_hang = True       # False: continuation lines start in column 1
    need_blank_after_title = False
    equals_open = []      # stack of open "=" blocks, as
                          # (input, output) delimiters
    text_block_depth = None  # len(equals_open) when a "[LABEL]" + "===="
                             # block opened, else None
    pending_admonition = False  # previous line was an uppercase "[LABEL]"
    indented_open = False  # inside an indented block
    indented_blanks = 0    # blank lines since the last indented-block line
    header = header_end(lines)  # lines before this index are the header

    def emit_blank():
        # Collapse runs of blank lines down to one.
        if out and out[-1] == "":
            return
        out.append("")

    def flush():
        nonlocal buf, buf_list_indent, buf_hang
        if not buf:
            return
        text = " ".join(s.strip() for s in buf)
        if buf_list_indent is not None:
            out.append(wrap_list_entry(text, buf_list_indent, buf_hang))
        else:
            out.append(wrap_paragraph(text))
        buf = []
        buf_list_indent = None
        buf_hang = True

    def dlist_entry(line):
        # Start a description list entry.  A term on a line by itself is
        # left unchanged, so the definition stays on the lines after the
        # term.  Otherwise the definition is wrapped, and the continuation
        # lines of the definition start in the first column.  Inside a
        # paragraph, a line such as "To do this, set::" is a continuation
        # line, not a new entry.  After a list entry, the line starts a
        # new entry.  Returns True if line starts an entry.  Returns False,
        # without flushing buf, otherwise.
        nonlocal buf, buf_list_indent, buf_hang
        if buf and buf_list_indent is None:
            return False
        marker_len = dlist_marker_len(line)
        if marker_len is None:
            return False
        flush()
        if marker_len >= len(line):
            out.append(line)
            return True
        buf = [line]
        buf_list_indent = marker_len
        buf_hang = False
        return True

    def verbatim_open(i, line):
        # Open a verbatim block if line is a "-", ".", or "```" block
        # delimiter.  Lines inside the block are handled at the top of
        # the main loop in process().  Returns True if a block was opened.
        nonlocal block_open, block_render
        delim = block_delim(line)
        if delim is None:
            return False
        flush()
        # For a bare "```" or "-" delimiter, block_render is "----" unless
        # the block holds a nested "-" delimiter.  For a "." delimiter,
        # block_render is "...." unless the block holds a nested "."
        # delimiter.  block_open keeps the input delimiter, because the
        # closing delimiter must be identical to the input delimiter.
        block_open = delim
        if line != delim:
            # An opening delimiter such as "```text" is left unchanged.
            # The closing "```" is also left unchanged.
            block_render = delim
            out.append(line)
            return True
        if _DOT_DELIM_RE.fullmatch(delim):
            block_render = delim_render(lines, i, delim, "....",
                                        _DOT_DELIM_RE)
        else:
            block_render = delim_render(lines, i, delim, "----",
                                        _DASH_DELIM_RE)
        out.append(block_render)
        return True

    def equals_delim(i, line):
        # An "=" delimiter identical to the opening delimiter of the
        # innermost open "=" block closes that block.  Any other "="
        # delimiter opens a new block.  Returns True if a block was opened.
        if equals_open and equals_open[-1][0] == line:
            out.append(equals_open.pop()[1])
            return False
        equals_open.append((line, delim_render(lines, i, line, "====",
                                               _EQUALS_DELIM_RE)))
        out.append(equals_open[-1][1])
        return True

    def indented_close():
        # Close an indented block.  Blank lines held back at the end of
        # the block become a single blank line.
        nonlocal indented_open, indented_blanks
        if indented_blanks:
            emit_blank()
        indented_open = False
        indented_blanks = 0

    for i, line in enumerate(lines):
        # Strip just the trailing newline; keep the rest of the line
        # exactly as-is so we can preserve block contents verbatim.
        raw = line.rstrip("\n")

        if i < header:
            # Header lines: any blank lines or comments, the document
            # title, then the author, revision, and attribute entries.
            # A blank line after the title would end the header early, so
            # no blank line is added after the title, and nothing is wrapped.
            line = to_ascii(raw).rstrip()
            if line == "":
                emit_blank()
            else:
                out.append(line)
            continue

        if indented_open:
            # Inside an indented block.  After a blank line, only an
            # indented line continues the block.  Directly after a non-blank
            # line, every line continues the block, except a block delimiter
            # or title.  Blank lines are held back until the next line shows
            # whether the block continues.
            s = raw.rstrip()
            if s == "":
                indented_blanks += 1
                continue
            if is_indented(raw) or (indented_blanks == 0
                                    and not block_delim(s)
                                    and not is_text_block_delim(s)
                                    and not is_title(s)):
                out.extend([""] * indented_blanks)
                indented_blanks = 0
                out.append(s)
                continue
            indented_close()

        if block_open is not None:
            # Inside a "-", ".", or "```" verbatim block, only a line
            # identical to block_open ends the block.  Every other line,
            # including lines that resemble titles or lists, is passed
            # through verbatim.
            # The closing delimiter is written as block_render.  A line such
            # as "```text" opens a block, but never ends a block.
            if raw.rstrip() == block_open:
                out.append(block_render)
                block_open = None
            else:
                out.append(raw)
            continue

        # A line indented by one or more spaces or tabs opens an
        # indented block when no paragraph or list entry is in progress.
        # An indented block also opens inside a "====" block.  An
        # indented line inside a paragraph or list entry is a
        # continuation line.
        if is_indented(raw) and not buf:
            if need_blank_after_title:
                emit_blank()
                need_blank_after_title = False
            pending_admonition = False
            out.append(raw.rstrip())
            indented_open = True
            continue

        # Outside any block: convert known non-ASCII characters to ASCII
        # equivalents and strip trailing whitespace.
        line = to_ascii(raw).rstrip()

        if text_block_depth is not None:
            # Inside a "[LABEL]" + "====" admonition block.  Paragraphs are
            # word-wrapped, and list entries are wrapped with continuation
            # lines aligned after the marker, as in the normal document flow.
            # Attribute lines, comments, block titles, table rows, attribute
            # entries, block macros, and "+" are left unchanged on their own
            # line, also as in the normal document flow.  The block ends at
            # the "=" delimiter identical to the opening delimiter.  The
            # delimiter stays on a line by itself.
            if is_text_block_delim(line):
                flush()
                equals_delim(i, line)
                if len(equals_open) < text_block_depth:
                    text_block_depth = None
                continue
            if verbatim_open(i, line):
                continue
            if line == "":
                flush()
                emit_blank()
                continue
            if dlist_entry(line):
                continue
            if (is_attribute(line) or is_comment(line)
                    or is_block_title(line) or is_table(line)
                    or is_attribute_entry(line) or is_block_macro(line)
                    or line == "+"):
                flush()
                out.append(line)
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

        # A "-----" underline also matches block_delim(), so check for a
        # "Title" + "-----" section title first and rewrite the title as
        # "== Title".
        title = setext_title(buf, buf_list_indent, line)
        if title is not None:
            buf = []
            out.append(title)
            need_blank_after_title = True
            continue

        if verbatim_open(i, line):
            continue

        if is_title(line):
            flush()
            out.append(line)
            need_blank_after_title = True
            continue

        if is_text_block_delim(line):
            flush()
            opened = equals_delim(i, line)
            # "[LABEL]" immediately followed by "====" opens a text block
            # whose contents are wrapped, until the identical "=" delimiter.
            # A bare "====" is only a delimiter on a line by itself.
            if was_pending and opened:
                text_block_depth = len(equals_open)
            continue

        # A line such as "[ statements ]:: text" starts a description list
        # entry.  is_attribute() matches any "[" line, so check for an
        # entry first.
        if dlist_entry(line):
            continue

        if is_attribute(line):
            flush()
            out.append(line)
            # Remember an uppercase "[LABEL]" so the next line can decide
            # whether it opens an admonition text block.
            if is_admonition_label(line):
                pending_admonition = True
            continue

        if (is_comment(line) or is_block_title(line) or is_table(line)
                or is_attribute_entry(line) or is_block_macro(line)):
            flush()
            out.append(line)
            continue

        if line == "+":
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
    if indented_open:
        indented_close()
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
