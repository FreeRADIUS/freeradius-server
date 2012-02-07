Upgrading to Version 3.0
========================

The configuration for 3.0 is *largely* compatible with the 2.x
configuration.  However, it is NOT possible to simply use the 2.x
configuration as-is.  Instead, you should re-create it.

Security
--------

A number of configuration items have moved into the "security"
subsection of radiusd.conf.  If you use these, you should move them.
Otherwise, they can be ignored.

The list of moved options is::

  chroot
  user
  group
  allow_core_dumps
  reject_delay
  status_server


Modules Directory
-----------------

As of version 3.0, the ``modules/`` directory no longer exists.

Instead, all "example" modules have been put into the
``mods-available/`` directory.  Modules which can be loaded by the server
are placed in the ``mods-enabled/`` directory.

Modules can be enabled by creating a soft link.  For module ``foo``, do::

  $ cd raddb
  $ ln -s mods-available/foo mods-enabled/foo

To create "local" versions of the modules, we suggest copying the file
instead.  This leaves the original file (with documentation) in the
``mods-available/`` directory.  Local changes should go into the
``mods-enabled/`` directory.


SQL
---

The SQL configuration has been moved from ``sql.conf`` to
``mods-available/sql``.  The ``sqlippool.conf`` file has also been
moved to ``mods-available/sqlippool``.

The SQL module configuration has been changed.  The old connection
pool options are no longer understood::

  num_sql_socks
  connect_failure_retry_delay
  lifetime
  max_queries

Instead, a connection pool configuration is used.  This configuration
contains all of the functionality of the previous configuration, but
in a more generic form.  It also is used in multiple modules, meaning
that there are fewer different configuration items.  The mapping
between the configuration items is::

  num_sql_socks			-> pool { max }
  connect_failure_retry_delay	-> NOT SUPPORTED
  lifetime			-> pool { lifetime }
  max_queries			-> pool { uses }

The pool configuration adds a number of new configuration options,
which allow the administrator to better control how FreeRADIUS uses
SQL connection pools.


EAP
---

The EAP configuration has been moved from ``eap.conf`` to ``mods-available/eap``.

It is otherwise unchanged.  You chould be able to copy your old
``eap.conf`` file directly to ``mods-enabled/eap``.


RadSec
------

RadSec (or RADIUS over TLS) is now supported.  RADIUS over bare TCP
is also supported, but is recommended only for secure networks.

See ``sites-available/tls`` for complete details on using TLS.  The server
can both receive incoming TLS connections, and also originate outgoing
TLS connections.

The TLS configuration is taken from the old EAP-TLS configuration.  It
is largely identical to the old EAP-TLS configuration, so it should be
simple to use and configure.  It re-uses much of the EAP-TLS code,
too.

Once RadSec is enabled, normal debugging mode will not work.  This is
because the TLS code requires threading to work properly.  Instead of doing::

  $ radiusd -X

you will need to do::

  $ radiusd -fxx -l stdout
