# Introduction

The server started off in 1999 as compatible with Livingston
radiusd-2.01 (no menus or s/key support though).  Over time is has
expanded to become the leading RADIUS server.

o Can limit the maximum number of simultaneous logins on a per-user basis!
o Multiple DEFAULT entries, that can optionally fall-through.
o In fact, every entry can fall-through
o Deny/permit access based on huntgroup users dials into
o Set certain parameters (such as static IP address) based on huntgroup
o Extra "hints" file that can select SLIP/PPP/rlogin based on
  username pattern (Puser or user.ppp is PPP, plain "user" is rlogin etc).
o Can execute an external program when user has authenticated (for example
  to run a sendmail queue).
o Can use `$INCLUDE filename' in radiusd.conf, users, and dictionary files
o Can act as a proxy server, relaying requests to a remote server
o Supports Vendor-Specific attributes
o Supports many different plug-in modules for authentication,
  authorization, and accounting.


# Installation

See the `INSTALL` file, in the parent directory.


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

    $ radiusd -X

Developers only discussion is to be had on the developers list:

http://lists.freeradius.org/mailman/listinfo/freeradius-devel

Please do not raise general configuration issues there.

# Other Information

  The files in other directories are:

  debian/	Files to build a "freeradius" Debian Linux package.

  doc/		Various snippets of documentation
  doc/rfc/	Copies of the RFC's.  If you have Perl, do a 'make' in
		that directory, and look at the HTML output.

  man/		Unix Manual pages for the server, configuration files,
		and associated utilities.

  mibs/		SNMP Mibs for the server.

  raddb/	Sample configuration files for the server.

  raddb/mods-available
  raddb/mods-enabled

  raddb/sites-available
  raddb/sites-enabled

  redhat/	Additional files for a RedHat Linux system.

  scripts/	Sample scripts for startup and maintenance.

  src/		Source code
  src/main	source code for the daemon and associated utilities
  src/lib	source code for the RADIUS library
  src/include	header files
  src/modules	dynamic plug-in modules

  suse/		Additional files for a SuSE (UnitedLinux) system.


If you have ANY problems, concerns, or surprises when running
the server, then run it in debugging mode, as root, from the
command line:

    $ radiusd -X

It will produce a large number of messages.  The answers to many
questions, and the solution to many problems, can usually be found in
these messages.

For further details, see:

http://www.freeradius.org/faq/

and the `bugs.md`  file, in this directory.

$Id$
