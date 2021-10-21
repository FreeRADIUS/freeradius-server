# Documentation

All of the documentation is now in Asciidoc format.  Please see the
[introduction](introduction/index.adoc) file for full details.

We also suggest reading the [directory](introduction/directory.adoc)
file, which describes the layout of this directory.

Please run the top-level `configure` script in order to create HTML
versions of the documentation.

## Antora

If the local system has [Antora
installed](https://docs.antora.org/antora/latest/install/install-antora/),
then you can run:

    make docsite

The output HTML is placed in the following location:

    ./build/docsite/freeradius-server/latest/index.html

If Antora is not installed locally, it can usually be installed from
`npm` (a command available once you install [Node.js](https://nodejs.org/)):

    npm i -g @antora/cli@2.0 @antora/site-generator-default@2.0

## Basic HTML

If the local system has Asciidoctor and Pandoc installed, then it is
possible to create simple HTML output via the following command:

    make html

The build process will create one `html` file for every `adoc` file in
this directory.  Note that Antora uses a different syntax for
cross-links than plain Asciidoc.  As a result, the output will look
OK, but links may be broken.

The main reason to use `make html` is that it can be faster than
Antora.  You can use this process to get a "quick look" at a rendered
page, to see if it looks reasonable.

The output HTML files are placed in the same directory as the input
Asciidoc files, with the extension changed to `.html`.

Note that the CSS for these HTML files is not in the `antora`
directories.  If you look at the files there, they will be missing the
CSS.  Instead, the `mods-available/always.adoc` file ends up being
accessible _only_ via `doc/raddb/mods-available/always.html`

## Raddb and Module Documentation

The documentation for each module syntax, configuration, etc. is
auto-generated from the files in the `raddb` directory.  Each
configuration file has some Asciidoc markup in the comments.  The file
`scripts/asciidoc/conf2adoc` takes care of converting configuration
files to Asciidoc.  See `all.mk` for specific commands.

When any documentation is built, the files in `raddb` are checked to
see if they are "out of date" with respect to the output `.adoc`
files.  If so, the `conf2adoc` script is run to refresh the Asciidoc files.
