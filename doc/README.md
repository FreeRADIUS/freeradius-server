# Installation

See the `INSTALL.md` file, in the parent directory.

# Configuration Files

For every file there is a fully commented example file included, that
explains what is does, and how to use it. Read those sample files too!

Again, many of the configuration files are ONLY documented in the
comments included in the files.  Reading the configuration files is
*required* to fully understand how to create complex configurations of
the server.

See the `raddb/radiusd.conf` file for the base configuration file.

# Additional information

The latest version of FreeRADIUS is always available from
the git repository hosted on GitHub at

https://github.com/FreeRADIUS/freeradius-server

There are two mailing lists for users and developers. General
user, administrator and configuration issues should be discussed
on the users list at:

http://lists.freeradius.org/mailman/listinfo/freeradius-users

When asking for help on the users list, be sure the include a
detailed and clear description of the problem, together with
full debug output from FreeRADIUS, obtained by running

    # radiusd -X

Developers only discussion is to be had on the developers list:

http://lists.freeradius.org/mailman/listinfo/freeradius-devel

Please do not raise general configuration issues there.

# Directories
## Documentation

| Directory			| Description
|---				|---
| ``debian/`` 			| Files to build a "freeradius" Debian Linux package.
| ``doc/``  			| Various snippets of documentation
| ``doc/rfc/``			| Copies of the RFC's.  If you have Perl, do a 'make' in that directory, and look at the HTML output.
| ``man/``			| Unix Manual pages for the server, configuration files, and associated utilities.

## Utility

| Directory			| Description
|---				|---
| ``mibs/``			| SNMP Mibs for the server.
| ``scripts/``			| Sample scripts for startup and maintenance.

## Configuration

| Directory			| Description
|---				|---
| ``raddb/``			| Sample configuration files for the server.
| ``raddb/mods-available``	| Module configuration files.
| ``raddb/mods-enabled``	| Directory containing symlinks to raddb/mods-available. Controls which modules are enabled.
| ``raddb/sites-available``	| Virtual servers.
| ``raddb/sites-enabled``	| Directory containing symlinks to raddb/sites-available. Control which virtual servers are enabled.

## Packaging
| Directory			| Description
|---				|---
| ``redhat/``			| Additional files for a RedHat Linux system.
| ``suse/``			| Additional files for a SuSE (UnitedLinux) system.

## Source
| Directory			| Description
|---				|---
| ``src/``			| Source code
| ``src/bin/``			| Source code for the daemon and associated utilities.
| ``src/lib/``			| Source code for various utility libraries.
| ``src/include/``		| Header files.
| ``src/protocols/``		| Dynamic frontend plug-in modules.
| ``src/modules/``		| Dynamic backend plug-in modules.

# Debugging

If you have ANY problems, concerns, or surprises when running
the server, then run it in debugging mode, as root, from the
command line:

    # radiusd -X

It will produce a large number of messages.  The answers to many
questions, and the solution to many problems, can usually be found in
these messages.

For further details, see:

https://www.freeradius.org/faq/

and the `bugs.md` file, in this directory.
