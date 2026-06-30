# Formatting files in the 'raddb' directory.

Most of the files in the `raddb` directory follow the FreeRADIUS
configuration file format which is documented in
doc/antora/modules/reference/pages/raddb/format.adoc

## Some files are not formatted

Some files in the `raddb` directory are loaded by a FreeRADIUS
modules, or for other software such as SQL schemas. Those files are
not part of the FreeRADIUS configuration, and should be ignored, and
should not be formatted.  The list of files to ignore is below:

* For the `raddb/mods-config` directory, ignore any files which do not end in `.conf`.

* ignore files where the filename is uppercase, e.g. `README`.

* ignore files which end in `.md`, `.txt` `.adoc`, or `.rst`.

* ignore files in the `raddb/certs` directory

* ignore dotfiles, i.e. files whose name begins with a `.`, e.g.
  `.gitignore` or `.DS_Store`.  These are not configuration files, and
  some (such as `.DS_Store`) are binary and cannot be read as text.

## Whitespace

The configuration files should use tabs for indentation, not spaces.
Tabs are 8 characters.  Leading spaces should be replaced by tabs.
Tabs and spaces should not be mixed.

When a section is opened (e.g. `section {`, the content is indented
one tab, including comments.  However, some configuration items in a
section may be commented out, in which case the `#` character is at
the start of the line, and the line contains a configuration setting
such as `foo = bar`.  In that case, the `#` character should be left
at the start of the line.

If there are backslashes at the end of a line for an `if` or `elseif`
statement, the backslash should be removed.

## Comments

Text inside of comments is indented with two spaces, except for code
examples, which are indented with either four spaces or a tab.

Large blocks of text in a comment are word wrapped at 79 characters.
If the indentation is more than 3 levels, the text word wrap is set to
an additional 8 characters for each level of indentation.

Large blocks of comments begin with an indented `#` all by itself.

Large blocks of comments end with an `#` all by itself.

### Contents of a comment section

When a file is mentioned in a comment, the filename is surrounded by
back-ticks, e.g. `/etc/raddb`.

When a configuration file is mentioned in a comment, the `raddb/`
prefix is not used.  If it is present, it should be removed.

A `NOTE:` in a comment section is uppercase.  If a lower-case or
mixed-case `Note:` is seen, it is converted to uppercase.  The same
rule applies to `TIP`, `WARNING`, and `IMPORTANT`.

## Conversion to Asciidoc

The script in `scripts/asciidoc/conf2adoc` converts the configuration
files to Asciidoc.  Comments are turned into normal text.
Configuration content is turned into code blocks.

### Configuration Section Documentation

Some configuration sections are preceded with a comment section that
summarizes what the configuration section is, and what it does.

A configuration section may begin with an Asiidoc title, e.g. `=
Title` or `== Subtitle` If the title uses `#` characters, it is
converted to using `=`.  For example:

```
# # This is a title
```

Should get converted to:

```
== This is a title
```

This applies to `## Subtitle` and sub-sub-titles, too.  However, if
there are tabs between the first and second `#` characters, then the
line is a commented-out comment, and is not a title.  It should not be
converted to a title.

If a configuration section begins with "dot" title, e.g. `.Example
Title`, it is converted to use `=`, of the appropriate depth.  But
text with two dots is not a title, and is not converted to use `=`.

Similarly, do not convert ".Example", or ".Return", ".Default", or
".Output" to a title with `=`.  Do not convert a "." which is followed
by a double-quote character.  Leave those strings alone.

If a section in `radiusd.conf` does not contain a title, print a
warning message.  A person then needs to edit the section and create
the title.

### Configuration Item Documentation

Some configuration items are preceded with a comment section that
summarizes what the configuration item is, and how it works.  That
comment section should begin with the name of the configuration item,
and then a double colon (e.g. '::'), followed by a one sentence
description of the what the configuration item does.

Cross-correlate the configuration item documentation.  If a
configuration item is documented in at least one place it does not
need to be documented elsewhere.  Consider the full parent section
hierarchy when doing this deduplication.  A configuration item `foo`
in a parent section `bar` is not the same as a configuration item
`foo` in parent section `stuff`.

In addition, within a single file, an item or section is considered
documented if any other item or section with the same name is
documented anywhere in that same file, regardless of parent hierarchy.
This avoids spurious warnings when a file documents `foo` once and
reuses the same name in a different sub-section.

Print a warning if a configuration item has no documentation, but only
if the `-w` flag is passed on the command line.

## Script Behavior

The script should take a command-line option '--format=name'.  if it
isn't set, all formatting is done.  Otherwise, the flag should control
which formatting is done.  Use a name of "headings" to reformat only
the headings.  Use "indent" to only do re-indenting.  Use "wrap" to
only do word wrapping.
