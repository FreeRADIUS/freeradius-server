Upgrading to Version 3.1
========================

.. contents:: Sections
   :depth: 2
   :
.. important::
   The configuration for 3.1 is *largely* compatible with the 3.0.x
   configuration.  It should be possible to reuse most of a 3.0.x
   reconfiguration with minor tweaks.
   If you're upgrading from v2.2.x you should read the version of
   this file which is included with v3.0.x releases.

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

In versions <= v3.0.x the config items for configuring connection
timeouts were either confusingly named, or completely absent in
the case of many contributed modules.

In v3.1.x connection timeouts can be configured universally for
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

The following modules have been changed.


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

In v3.1.x they must now be specified as::

  count_attribute	= &Acct-Session-Time
  counter_name		= &Daily-Session-Time
  check_name		= &control:Max-Daily-Session
  reply_name		= &reply:Session-Timeout
  key			= &User-Name

Just adding the '&' prefix is not sufficient.  Attributes must be qualified
with the list to search in, or add to.

This allows significantly greater flexibility, and better integration with
newer features in the server such as CoA, where reply_name can now be
``&coa:Session-Timeout``.


allowed_service_type
++++++++++++++++++++

The ``allowed_service_type`` config item of the rlm_counter module has
also been removed, as it was duplicative of functionality afforded by unlang.


Database format compatibility (rlm_counter)
+++++++++++++++++++++++++++++++++++++++++++

GDBM counter databases from <= v3.0.x are not compatible with those from
v3.1.x as the width of the counter was changed from 32bits to 64bits.
