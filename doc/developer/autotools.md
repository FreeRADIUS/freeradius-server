FreeRADIUS use of GNU autotools
===============================

The full autotools suite includes many utilities, which we do not
need or want to use. Especially libtool, for which we use the
faster replacement, jlibtool.

In a normal autotools setup, one would run "autoreconf" to rebuild
all of the configure scripts, which will perform at least the
following tasks:

  - aclocal
  - autoconf
  - autoheader
  - automake
  - libtoolize

Specifically, all we really want to run is `autoconf`, to rebuild
the configure scripts.

We have a more complicated setup than most. There is normally just
one `configure` script, in the top-level directory. In FreeRADIUS
there are also configure scripts in most RLM module directories as
well. Autotools is not really set up to handle this well,
preferring to treat every sub-directory as a separate project.

This means that e.g. cache files are not shared, and include files
(for configure macros) are not found as they are expected to be in
the current directory.

What's more, autoconf macros can be found in multiple places - the
automake install directory, the system aclocal directory, and in
multiple places in the FreeRADIUS source (mainly `m4/`, but also
`acinclude.m4`, both potentially in multiple places).

In our setup we want to run the following only:

  - autoconf, to generate configure files and `all.mk` make files.
  - autoheader, to generate header files.


autoconf
--------

`autoconf` expands a `configure.ac` file to create a `configure`
script, with optionally also a Makefile. We generate a makefile
called `all.mk` to work with the boilermake system.

Being based on m4, autoconf needs to find macro definitions from
somewhere, which will be expanded as needed upon invocation.
autoconf has several search paths for macros, including some
system paths for its own internal macros.

Notably within the project, autoconf looks in `aclocal.m4` to find
"local" macros to add. These days, `aclocal.m4` is supposed to be
written by the `aclocal` script, so autotools added the concept of
`acinclude.m4` to put local macros. `aclocal` will add an include
directive at the bottom of `aclocal.m4` to include the
`acinclude.m4` file, if it is found in the current directory.

When `aclocal` is run it will scan `configure.ac` for anything
that looks like a macro to expand. It will then search project
directories, the automake system directory and the aclocal system
directory, to find any macros that match. These are copied into
the `aclocal.m4` file. `autoconf` will then pick up these macro
definitions and use them when expanding `configure.ac`. Notably,
macros can be in `*.m4` files in given search directories and
`aclocal` will extract the macros and copy them over.

`autoconf` itself will not look in `*.m4` files, only in
`aclocal.m4` and, if that is not found, `acinclude.m4`.

We therefore have, _within one level directory_:

  - `acinclude.m4`, local macro definitions;
  - `aclocal.m4`, macros collated by `aclocal`;
  - `m4/` or other directories, macro files searched by `aclocal`;
  - `configure.ac` the input configure script;
  - `all.mk`, `configure`, etc as outputs from `autoconf`.

The GNU Autotools manual these days recommends splitting macros
up, one file per macro, and putting them in the `m4/` directory
rather than in the `acinclude.m4` file. This makes them much
easier to maintain.


FreeRADIUS sub-directories
--------------------------

All the above is not too much of an issue for the top-level
configure script. We can have an automatically generated
`aclocal.m4` file, macros in `m4/` and extra components in
`acinclude.m4` if needed. However, the sub-directory configure
scripts really want to be kept as small as possible. There is no
real need for a separate `aclocal.m4` file if all of the configure
scripts could be scanned together. The top-level `m4/` directory and
`acinclude.m4` file can be used.

Unfortunately, autotools doesn't like to work like this. It wants
all files to be in one directory, and `aclocal` won't scan more
than one `configure.ac` file.

The two compromise solutions seem to be:

 - Don't use `aclocal`.

    - Nearly all local macros are put in the top-level
      `acinclude.m4` file.
    - A few local macros can go in `m4/`, but they have to
      explicitly included in configure.ac scripts with
      `m4_include()`.
    - `autoconf` has to be run with multiple `-I` include args to
      capture all the places where macros could be.
    - Any missing macros won't get pulled in from system
      locations, because `aclocal` noramally does that.
    - Sub-directories are relatively clean, e.g. no `aclocal.m4`
      or `acinclude.m4` files all over the place.

 - Use `aclocal`.

    - The `-I` arg can be passed to `aclocal` which makes it
      search multiple project directories for local macros to copy
      to `aclocal.m4`.
    - All directories with a `configure` script must have an
      `aclocal.m4` file to collate macros from the top-level `m4/`
      directory.
    - The top-level `acinclude.m4` file is ignored except in the
      top-level configure script, meaning it needs to be symlinked
      or copied everywhere else.
    - If `autoconf` finds an `aclocal.m4` file it no longer seems
      to look for macros elsewhere.
    - Sub-directories get messy with `aclocal.m4` and
      `acinclude.m4` files, though these don't need to be checked
      into the repository.
    - The top-level `m4/` directory can contain all macros as
      separate files, which is much cleaner than `acinclude.m4`.
    - System macros will be found and used.

We pretty much need to use `aclocal` - it removes the need for an
`acinclude.m4` file (tidier), picks up macros from `m4/`
automatically (tidier), removes the need for `m4_include()` macros
(tidier), and means that macros will be found that might not be
shipped in the FreeRADIUS distribution (easier).

That comes with some downsides as above - we will end up with
`aclocal.m4` files all over the place, and have to handle the case
where things were originally in `acinclude.m4` and are not macros.

Fixing `aclocal.m4` files can be done by either including them in
git (unnecessary) or hiding them with `.gitignore` (best).

Picking up non-macro definitions from `acinclude.m4` can be done
by adding a new macro, `FR_INIT()`, which defines anything needed.
In fact, as long as that macro is included, the _entire_
`m4/fr_init.m4` file will be included by `aclocal`. This means the
extra definition doesn't even need to be inside the macro.


Rebuilding the configure scripts
================================

The normal way to rebuild all of the autotools outputs is to run
`autoreconf`. This must not be run with FreeRADIUS as it will
initialise and use libtool and other things we do not want.

Instead, we have a make target to rebuild everything needed.

    make reconfig

This will rebuild any configure files that are out of date.
However, sometimes everything needs to be forced, e.g. due to some
macros changing that are missed by the Make dependencies (maybe
from the system directories). In this case a forced rebuild can be
undertaken with:

    find . -name configure.ac | xargs touch
    make reconfig

This will ensure that _all_ configure scripts are rebuilt.
