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
