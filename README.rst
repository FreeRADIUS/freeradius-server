The FreeRADIUS server
=====================

|BuildStatus|_ |CoverityStatus|_

.. contents::
   :local:

Introduction
------------

The FreeRADIUS Server Project is a high performance and highly
configurable multi-protocol policy server, supporting RADIUS, DHCPv4
and VMPS. It is available under the terms of the GNU GPLv2.
Using RADIUS allows authentication and authorization for a network
to be centralized, and minimizes the number of changes that have to
be done when adding or deleting new users to a network.

FreeRADIUS can authenticate users on systems such as 802.1x (WiFi),
dialup, PPPoE, VPN's, VoIP, and many others.  It supports back-end
databases such as MySQL, PostgreSQL, Oracle, Microsoft Active
Directory, Apache Cassandra, Redis, OpenLDAP, and many more.  It is
used daily to authenticate the Internet access for hundreds of millions
of people, in sites ranging from 10 to 10 million+ users.

The v3.1.x branch
-----------------

v3.2.0 was scheduled to be an 'engineering' release of the v3.0.x series.
In order to reduce confusion with multiple versions being released in 
quick succession, the next public release will be from the v4.0.x branch.

v4.0.x is almost entirely config compatible with v3.1.x.

**No further bug fixes or development will be done on the v3.1.x branch.  Use v4.0.x instead.**

.. |CoverityStatus| image:: https://scan.coverity.com/projects/58/badge.svg?
.. _CoverityStatus: https://scan.coverity.com/projects/58

.. |BuildStatus| image:: https://travis-ci.org/FreeRADIUS/freeradius-server.png?branch=v3.1.x
.. _BuildStatus: https://travis-ci.org/FreeRADIUS/freeradius-server
