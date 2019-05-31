# FreeRADIUS Documentation

This directory contains documentation for FreeRADIUS.  The
documentation is available under the Creative Commons Non-Commercial
license, as given in the `LICENSE` file in this directory.

[Introduction](introduction/) - Introduction to FreeRADIUS and RADIUS
in general.

[Upgrading](upgrade/) - How to upgrade from version 3 to version 4.

[How-To](howto/) - How-To guides for performing common tasks.

[Unlang Reference](unlang/) - reference documentation for unlang.

[Configuration Files](raddb/) - Documentation for the files in the
`raddb` directory.  This documentation includes configuration files
which have been converted to Asciidoc

[Developer Documentation](source/) - API / developer documentation.  Most people can ignore this.

## Installation

Please see the `INSTALL.md` file, in the parent directory.

Pre-build packages for common Linux systems are available at
http://packages.networkradius.com/

## Configuration Files

Every configuration file contains documentation that explains in
detail what it does, and what each configuration item does.

Reading the configuration files is *required* to fully understand how
to create complex configurations of the server.

## Getting Help

There are two mailing lists for users and developers. General
user, administrator and configuration issues should be discussed
on the users list at:

http://lists.freeradius.org/mailman/listinfo/freeradius-users

When asking for help on the users list, be sure the include a
detailed and clear description of the problem, together with
full debug output from FreeRADIUS, obtained by running

    # radiusd -X

## Where to get it

The latest version of FreeRADIUS is always available from
the git repository hosted on GitHub at

https://github.com/FreeRADIUS/freeradius-server

## Directories

There are a number of directories included here:

### Documentation

| Directory			| Description
|---				|---
| ``debian/`` 			| Files to build a "freeradius" Debian Linux package.
| ``doc/``  			| Various snippets of documentation
| ``doc/rfc/``			| Copies of the RFC's.  If you have Perl, do a 'make' in that directory, and look at the HTML output.
| ``man/``			| Unix Manual pages for the server, configuration files, and associated utilities.

### Utility

| Directory			| Description
|---				|---
| ``mibs/``			| SNMP Mibs for the server.
| ``scripts/``			| Sample scripts for startup and maintenance.

### Configuration

| Directory			| Description
|---				|---
| ``raddb/``			| Sample configuration files for the server.
| ``raddb/mods-available``	| Module configuration files.
| ``raddb/mods-enabled``	| Directory containing symlinks to raddb/mods-available. Controls which modules are enabled.
| ``raddb/sites-available``	| Virtual servers.
| ``raddb/sites-enabled``	| Directory containing symlinks to raddb/sites-available. Control which virtual servers are enabled.

### Packaging
| Directory			| Description
|---				|---
| ``redhat/``			| Additional files for a RedHat Linux system.
| ``suse/``			| Additional files for a SuSE (UnitedLinux) system.

### Source
| Directory			| Description
|---				|---
| ``src/``			| Source code
| ``src/bin/``			| Source code for the daemon and associated utilities.
| ``src/lib/``			| Source code for various utility libraries.
| ``src/include/``		| Header files.
| ``src/protocols/``		| Dynamic frontend plug-in modules.
| ``src/modules/``		| Dynamic backend plug-in modules.

## Debugging

If you have ANY problems, concerns, or surprises when running
the server, then run it in debugging mode, as root, from the
command line:

    # radiusd -X

It will produce a large number of messages.  The answers to many
questions, and the solution to many problems, can usually be found in
these messages.

For further details, see:

http://wiki.freeradius.org/radiusd-X
