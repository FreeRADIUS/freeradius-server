= Welcome to Version 4.0 of FreeRADIUS

WARNING: **PLEASE DO NOT USE VERSION 4.  IT IS INTENDED ONLY FOR
DEVELOPERS.  THE CONFIGURATION MAY CHANGE.  THE BEHAVIOR MAY CHANGE.
THE DOCUMENTATION MAY CHANGE.**

Version 4 is the result of years of effort by the FreeRADIUS
developers.  The goal of v4 was to expand it's feature set.  Many
features could not be implemented because of limitations that have
been in the server since the beginning of the project.  For example,
in v3 and earlier releases, we had the following limitations:

* it was impossible to proxy one packet to multiple destinations

* it was impossible to catch a "failed" proxy, and fall back to local
  authentication

* the server could not support multiple clients with different shared
  secrets behind one NAT gateway

* the DHCP and VMPS was implemented by making them pretend to be
  RADIUS, which limited their functionality

* the server did not support TACACS+

* connections to databases were "synchronous".  If a database blocked,
  it could eventually lock up the server

All of these limitations and more have been removed.  The downside of
these changes is that the some of the configuration has been changed.
Please see the [`UPGRADE.md`](UPGRADE.md) file for instructions on
how to migrate a v3 configuration to v4.

## Configuring the server

When configuring the server, please start with the default
configuration.  It is intended to work in the widest possible
circumstances, with minimal site-local changes.  Most sites can just
configure a few modules such as `ldap` and `sql`, and the server will
do everything you need.  More complex configurations require more
effort, of course.

For more complex configurations, the best approach is to make a series
of small changes.  Start the server after every change via `radiusd
-XC` to see if the configuration is OK.  Use `radclient` to send the
server test packets.  Read the debug output (`radiusd -X`) to verify
that the server is doing what you expect.

For complex policies, it is best to write down what you want in plain
English.  Be specific.  Write down what the server receives in a
packet, which databases are used, and what the database should return.
The more detailed these explanations, the easier it will be to create
a working configuration.

Take your time.  It is better to make small incrementatal progress,
than to make massive changes, and then to spend weeks debugging it.

## Organization

The files in this directory are organized into logical groups, as
follows.

* `mods-available/` - [Available modules](mods-available/README.md), with example configuration.

* `mods-enabled/` - Enabled modules that are being used by FreeRADIUS.

* `sites-available/` - [Available virtual servers](sites-available/README.md), with example configuration.

* `sites-enabled/` - Enabled virtual servers that are being used by FreeRADIUS.

* `policy.d/` - example and live policies which implement standard rules and checks.

* `certs/` - Certificiates for EAP and for RADIUS over TLS.

The directories are descrived in more detail below.

### `mods-available/`

The `mods-available/` directory contains configuration for all of the
available modules.  Each module configuration is different.  Each file
contains documentation that describes what the module is, and how it
works.

The directory contains almost 100 modules.  Most configurations will
only use a few modules.  The rest exist in order to serve as
documentation and worked examples.

### `mods-enabled/`

The `mods-enabled/` directory contains the *enabled* modules.  The
files here should generally be soft links back to the
`mods-available/` directory.

For example, the following commands would enable the `ldap` module:

    cd mods-enabled/
    ln -s ../mods-available/ldap

Note that the `ldap` module must still be configured for the local systems.

### `mods-config/`

This directory contains complex configuration files for modules loaded
from `mods-enabled/`.

For example, the `sql` module can connect to multiple types of SQL
databases.  Each SQL database has it's own schema, along with default
queries for RADIUS, IP pools, DHCP, etc.  If these files were placed
into the 'mods-available/` directory, that directory would get compled
and difficult to manage.

Instead, the files are placed into a separate directory.

Note that only a few modules require this extra configuration.

### `policy.d`

The `policy.d/` directory contains sample policies that are used when
processing packets.  These policies implement complex logic which
often uses multiple modules.

There is no need to have "available" or "enabled" policies.  All
policies are loaded by the server, and unused ones are ignored.

### `sites-available/`

The `sites-available/` directory contains virtual servers which
process packets.  They are similar to the virtual servers used by
Apache or Nginx.

Each virtual server will begin with a `server` declaration, along with
it's name.  e.g. `server default { ...`.  The declaration is then
followed by a `namespace = ` parameter, which describes which
application protocol is being used in that virtual server.
e.g. `namespace = radius`.

The virtual server will then contain zero or more `listen`
subsections.  Each `listen` subsection defines a network socket which
is used to receive packets.

The virtual server will then contain multiple `recv` and `send`
subsections.  These subsections are used to process packets.

Note that unlike v3, there are no longer any `authorize`,
`authenticate`, etc. sections.  All of the "processing sections" have
been renamed.  This change was necessary in order to simplify the
operation of the server, and to better support multiple protocols.

Please see the [`UPGRADE.md`](UPGRADE.md) file for more
information about these changes.

The `sites-available/` directory contains many files.  Each file is a
worked example of how to achieve a particular goal using FreeRADIUS.
We recommend reading these files in order to see how complex goals can
be achieved.

### `sites-enabled/`

The `sites-enabled/` directory contains the *enabled* virtual servers.  The files here should
generally be soft links back to the `sites-available/` directory.

For example, to enable the `default` virtual server, you can run these commands:

    cd sites-enabled/
    ln -s ../sites-available/default

The standard installation of FreeRADIUS enables only a few virtual servers.

### `certs/`

This directory contains certificates and configuration for EAP and
RADIUS over TLS (i.e. RadSec).

## List of config files

<!--- FILE_LIST(raddb)
      Do not remove - this will be expanded when converting to Asciidoc -->
