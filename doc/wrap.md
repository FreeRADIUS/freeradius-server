# Word Wrapping Asciidoc Files

The "*.adoc" files should have all text paragraphs wrapped at 80
columns.

If there are multiple blank lines in a row, then the output should
contain only one blank line.

Trailing spaces on lines should be removed.

Comments are lines that begin with "//", and should not be wrapped

Titles are lines that begin with "#" or "=", and should not be
wrapped.  There should be a blank line after a title.

Inline blocks are a series of lines that begin and end with "----".
The inline blocks should not be wrapped.

Inline block titles are lines that begin with ".", and should not be
wrapped.

Code blocks are a series of lines that begin and end with "```".
The inline blocks should not be wrapped.

Tables are lines that start with begin with "|".  Tables should not be
wrapped.

Paragraphs should have a blank line between them.

List entries are lines that start with "* " or "- ".  They should be
wrapped individually.  That is, each list entry should be word wrapped
all by itself, and should not include text from other list entries.
If a list entry spans multiple lines, the second line should be
indented another 2 spaces, so that it is aligned with the text, and
not with the leading "* ".
