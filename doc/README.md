# Documentation

All of the documentation is now in "asciidoc" format.  Please see the
[introduction](introduction/index.adoc) file for full details.

We also suggest reading the [directory](introduction/directory.adoc)
file, which describes the layout of this directory.

Please run the top-level `configure` script in order to create HTML
versions of the documentation.

## Basic HTML

If the local system has Asciidoctor and Pandoc installed, then it is
possible to create simple HTML output via the following command:

    $ make html

The build process will create one `html` file for every `adoc` file in
this directory.

## Antora

If the local system has Antora installed, then it is possible to
create much more useful HTML output fix the following command:

    $ antora site.yml

The output HTML is placed in the following location:

    ./build/site/freeradius-server/latest/index.html

If Antora is not intalled localled, it can usually be installed from
`npm`:

    $ npm i -g @antora/cli@2.0 @antora/site-generator-default@2.0
