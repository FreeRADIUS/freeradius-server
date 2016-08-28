Upgrading to Version 4.0
========================

.. contents:: Sections
   :depth: 2
   :
.. important::
   The configuration for 4.0 is *somewhat* compatible with the 3.0.x
   configuration.  It should be possible to reuse most of a 3.0.x
   reconfiguration with minor tweaks.
   If you're upgrading from v2.2.x you should read the v3.0.x version
   of this file.  It describes changed from v2 to v3.0.  This file
   describes only the changes from v3.0 to v4.0

Processing Sections
-------------------

All of the processing sections have been renamed.  Sorry, but this was
required for the new features in v4.

========		========
Old Name		New Name
--------		--------
authorize		recv Access-Request
authenticate		process <Auth-Type>
post-auth		send Access-Accept

preacct			recv Accounting-Request
accounting		send Accounting-Response

recv-coa		recv CoA-Request
send-coa		send CoA-ACK
send-coa		send CoA-NAK

Post-Auth-Type Reject	send Access-Reject
Post-Auth-Type Challenge  send Access-Challenge
========                ========

i.e. instead of the section names being (mostly) randomly named, the
names are now consistent.  `recv` receives packets from the network.
`send` sends packets back to the network.  The second name of the
processing section is the *type* of the packet which is being received
or sent.


Dictionaries
------------

The `struct` data type is now supported.  See `man dictionary`.

There are many more sanity checks and helpful messages for people
creating new dictionaries.

Attribute references
--------------------

In previous versions of the user attributes could be referred to
by their name only e.g. ``if (User-Name == 'foo')``.

To allow for more thorough error checking, the requirement to prefix
attribute references with '&' is now strictly enforced.

Common places which will need to be checked and corrected are the
left and right hand side of ``update {}`` sections, and conditions.

v3.0.x has warned about using non prefixed attribute references for
some time.  If users have paid attention to those warnings no
modifications will be required.

Use of attributes in xlats e.g. ``%{User-Name}`` remains unchanged.
There is no plan to require prefixes here.

Connection timeouts
-------------------

In v2.2 and earlier, the config items for configuring connection
timeouts were either confusingly named, or completely absent in
the case of many contributed modules.

In v4.0.x connection timeouts can be configured universally for
all modules with the ``connect_timeout`` config item of the
module's ``pool {}`` section.

The following modules should honour ``connect_timeout``:

- rlm_smsotp
- rlm_rest
- rlm_linelog (network connections only)
- rlm_ldap
- rlm_couchbase
- rlm_cache_memcached
- rlm_redis_* (all the redis modules)
- rlm_sql_cassandra
- rlm_sql_db2
- rlm_sql_freetds
- rlm_sql_iodbc
- rlm_sql_mysql
- rlm_sql_unixodbc

Some modules such as rlm_sql_postgresql can have their timeout set via an alternative
configuration item (``radius_db`` in the case of postgresql).

Changed Modules
---------------

The following modules exhibit changed behaviour.

rlm_cache
~~~~~~~~~

``&control:Cache-Merge`` has been renamed to ``&control:Cache-Merge-New`` and controls 
whether new entries are merged into the current request.  It defaults to ``no``.
The primary use case, is if you're using xlat expansions in the cache module itself
to retrieve information for caching, and need the result of those expensions to be
available immediately.

Two new control attributes ``&control:Cache-Allow-Merge`` and ``&control:Cache-Allow-Insert``
have been added.  These control whether existing entries are to be merged, and new entries
created on the next call to a cache module instance. Both default to ``yes``.

rlm_eap
~~~~~~~

All certificate attributes are available in the ``&session-state:`` list,
immediately after they're parsed from their ASN1 form.

The certificates are longer added to the ``&request:`` list.  You are
advised to update any references during the upgrade to 4.0:

    ``s/TLS-Cert-/session-state:TLS-Cert-/``.

The ``rlm_eap_ikev2`` module was removed.  It does not follow RFC
5106, and no one was maintaining it.

The ``rlm_eap_tnc`` module was removed.  No one was using or maintaining it.

The in-memory SSL cache was removed.  Changes in OpenSSL and
FreeRADIUS made it difficult to continue using the OpenSSL
implementation of a cache.  See ``raddb/sites-available/tls-cache``
for a better replacement.  The OpenSSL cache can now be placed on
disk, in memory, in memcache, or in a redis cache.  The result is
higher performance, and is more configurable.

The ``use_tunneled_reply`` and ``copy_request_to_tunnel``
configuration items have been removed.  Their functionality has been
replaced with the ``use_tunneled_reply`` and
``copy_request_to_tunnel`` policies.  See
``raddb/sites-available/inner-tunnel`` and ``raddb/policy.d/eap`` for
more information.

These configuration items were removed because they caused issues for
a number of users, and they made the code substantially more
complicated.  Experience shows that having configurable policies in
``unlang`` is preferable to having them hard-coded in C.

rlm_expr
~~~~~~~~

Allow `&Attr-Name[*]` to mean "sum".  Previously, it just referred to
the first attribute.

Using `%{expr:0 + &Attr-Name[*]}` will cause it to return the sum of the values
of all attributes with the given name.

Note that `%{expr:1 * &Attr-Name[*]}` does *not* mean repeated
multiplication.  Instead, the sum of the attributes is taken as
before, and then the result is multiplied by one.


rlm_rest
~~~~~~~~

``REST-HTTP-Code`` is now inserted into the ``&request:`` list instead of the ``&reply:``
list, to be compliant with the list _usage guidelines.

.. _usage: http://wiki.freeradius.org/contributing/List-Usage

rlm_sqlcounter and rlm_counter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Attribute references
++++++++++++++++++++

The following config items must now be defined as attribute references::

  key
  count_attribute
  counter_name
  check_name
  reply_name

For example where in v3.0.x you would specify the attribute names as::

  count_attribute	= Acct-Session-Time
  counter_name		= Daily-Session-Time
  check_name		= Max-Daily-Session
  reply_name		= Session-Timeout
  key			= User-Name

In v4.0.x they must now be specified as::

  count_attribute	= &Acct-Session-Time
  counter_name		= &Daily-Session-Time
  check_name		= &control:Max-Daily-Session
  reply_name		= &reply:Session-Timeout
  key                   = &User-Name

Just adding the '&' prefix is not sufficient.  Attributes must be qualified
with the list to search in, or add to.

This allows significantly greater flexibility, and better integration with
newer features in the server such as CoA, where reply_name can now be
``&coa:Session-Timeout``.


allowed_service_type
++++++++++++++++++++

The ``allowed_service_type`` config item of the rlm_counter module has
also been removed, as it duplicated existing functionality.


rlm_sql_mysql
~~~~~~~~~~~~~

Now calls ``mysql_real_escape_string`` and no longer produces
``=<hexit><hexit>`` escape sequences in expanded values.
The ``safe_characters`` config item will have no effect when used with
this driver.

rlm_sql_postgresql
~~~~~~~~~~~~~~~~~~

Now calls ``PQescapeStringConn`` and no longer produces ``=<hexit><hexit>``
escape sequences in expanded values.  The ``safe_characters`` config item will
have no effect when used with this driver.

Deleted Modules
---------------

The following modules have been deleted

rlm_counter
~~~~~~~~~~~

Please use rlm_sqlcounter with sqlite.


rlm_ippool
~~~~~~~~~~

Please use rlm_sql_ippool with sqlite.

rlm_sql
~~~~~~~

Driver-specific options have moved from ``mods-available/sql`` to
``mods-config/sql/driver/<drivername>``.

