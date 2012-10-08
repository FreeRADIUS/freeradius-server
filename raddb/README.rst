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

The following parameters have been changed::

  trace				-> removed
  tracefile			-> logfile

The logfile is intended to log SQL queries performed.  If you need to
debug the server, use debugging mode.  If ``logfile`` is set, then
*all* SQL queries will go to ``logfile``.

You can now use a NULL SQL database::

  driver = rlm_sql_null

This is an empty driver which will always return "success".  It is
intended to be used to replace the ``sql_log`` module, and in
conjunction with the ``radsqlrelay`` program.  Simply take your normal
configuration for raddb/mods-enabled/sql, and set::

  driver = rlm_sql_null
  ...
  logfile = ${radacctdir}/log.sql

And all of the SQL queries will be logged to that file.  The
connection pool	will still need to be configured for the NULL SQL
driver, but the defaults will work.

SQL-dialup.conf
---------------

Queries for post-auth and accounting calls have been re-arranged.
The SQL module will now expand the 'reference' configuration item
in the appropriate sub-section, and resolve this to a configuration
item. This behaviour is similar to rlm_linelog.

The queries can manually be moved to copy of the v3.0.x ``dialup.conf`` file.
The mapping is as follows::

  accounting_onoff_query		-> accounting.type.accounting-on.query
  accounting_update_query		-> accounting.type.interim-update.query
  accounting_update_query_alt		+> accounting.type.interim-update.query
  accounting_start_query		-> accounting.type.start.query
  accounting_start_query_alt		+> accounting.type.start.query
  accounting_stop_query			-> accounting.type.stop.query
  accounting_stop_query_alt		+> accounting.type.stop.query
  postauth_query			-> post-auth.query

References to to the accounting tables may also need to be updated.

Alternitavely a v2.1.x may be patched to work with the v3.0.x module.
Add the following at the bottom of your ``dialup.conf`` file::

  accounting {
  	reference = "%{tolower:type.%{Acct-Status-Type}.query}"
  	type {
  		accounting-on {
  			query = "${....accounting_onoff_query}"
  		}
  		accounting-off {
  			query = "${....accounting_onoff_query}"
  		}	
   		start {
  			query = "${....accounting_start_query}"
  			query = "${....accounting_start_query_alt}"
  		}
  		interim-update {
  			query = "${....accounting_update_query}"
  			query = "${....accounting_update_query_alt}"
  		}
  		stop {
  			query = "${....accounting_stop_query}"
  			query = "${....accounting_stop_query_alt}"
  		}
  	}
  }

  post-auth {
  	query = "${..postauth_query}"
  }

EAP
---

The EAP configuration has been moved from ``eap.conf`` to
``mods-available/eap``.  A new ``pwd`` subsection has been added for
EAP-PWD.

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
so it is well-tested and reliable.

Once RadSec is enabled, normal debugging mode will not work.  This is
because the TLS code requires threading to work properly.  Instead of doing::

  $ radiusd -X

you will need to do::

  $ radiusd -fxx -l stdout


PAP and User-Password
---------------------

From version 3.0 onwards the server no longer supports authenticating
against a cleartext password in the 'User-Password' attribute. Any
occurances of this (for instance, in the users file) should now be changed
to 'Cleartext-Password' instead.

If this is not done, authentication is likely to fail.

If it really is impossible to do this, the following unlang inserted above
the call to the pap module may be used to copy User-Password to the correct
attribute::

  if (!control:Cleartext-Password && control:User-Password) {
    update control {
      Cleartext-Password := "%{control:User-Password}"
    }
  }

However, this should only be seen as a temporary, not permanent, fix.
