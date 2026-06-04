# Word Wrapping Asciidoc Files

The "*.adoc" files should have all text paragraphs wrapped at 80
columns.

If there are multiple blank lines in a row, then the output should
contain only one blank line.

Trailing spaces on lines should be removed.

Non-ASCII characters get converted to equivalent ASCII ones, according
to the following Perl regular expression:

    "s,‘,',g;s,’,',g;s,–,-,g;s,—,-,g;s, , ,g;s:…:,:g;s,“,\",g;s,”,\",g;s,≤,<=,g;s,≥,>=,g;s,→,->,g"

Comments are lines that begin with "//", and should not be wrapped

Titles are lines that begin with "#" or "=", and should not be
wrapped.  There should be a blank line after a title.

Inline code blocks are a series of lines that begin and end with
"----".  The inline code blocks should not be wrapped.  The contents
of an inline block should not be formatted, but should instead be left
as-is.

Inline block titles are lines that begin with ".", and should not be
wrapped.

Notes, warnings, etc. are words that begin with '[', e.g. [NOTE].
They should be on a line by themselves.

Text blocks begin and end with "====".  The contents of the text
blocks should be word wrapped.  But the "====" lines need to be on
their own line.

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

Numbered list entries are lines that start with a number, followed by
a dot.  e.g. "1.".  Those list entries should be word wrapped just
like the "*" list entries. The leading number should remain unchanged.