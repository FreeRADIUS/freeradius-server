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

Upgrading
---------
Version 3.1.x of the server is largely compatible with version 3.0.x,
but be sure to address any warnings when starting v3.0.x before
attempting to use en existing configuration with v3.1.x.

For a list of changes in version 3.1, please see ``doc/ChangeLog``.

See ``raddb/README.rst`` for information on what to do to update your
configuration.

Administrators upgrading from a previous version should install this
version in a different location from their existing systems.  Any
existing configuration should be carefully migrated to the new
version, in order to take advantage of the new features which can
greatly simply configuration.

Please see http://freeradius.org and http://wiki.freeradius.org for
more information.


Installation
------------

To install the server, please see the INSTALL file in this directory.

Configuring the server
----------------------

We understand that the server may be difficult to configure,
install, or administer.  It is, after all, a complex system with many
different configuration possibilities.

The most common problem is that people change large amounts of the
configuration without understanding what they're doing, and without
testing their changes.  The preferred method of operation is the
following:

1. Start off with the default configuration files.
2. Save a copy of the default configuration: It WORKS.  Don't change it!
3. Verify that the server starts - in debugging mode (``radiusd -X``).
4. Send it test packets using "radclient", or a NAS or AP.
5. Verify that the server does what you expect

   - If it does not work, change the configuration, and go to step (3)
   - If you're stuck, revert to using the "last working" configuration.
   - If it works, proceed to step (6).
  
6. Save a copy of the working configuration, along with a note of what
   you changed, and why.
7. Make a SMALL change to the configuration.
8. Repeat from step (3).

This method will ensure that you have a working configuration that
is customized to your site as quickly as possible.  While it may seem
frustrating to proceed via a series of small steps, the alternative
will always take more time.  The "fast and loose" way will be MORE
frustrating than quickly making forward progress!

Debugging the Server
--------------------

Run the server in debugging mode, (``radiusd -X``) and READ the output.
We cannot emphasize this point strongly enough.  The vast majority of
problems can be solved by carefully reading the debugging output,
which includes WARNINGs about common issues, and suggestions for how
they may be fixed.

Read the FAQ.  Many questions are answered there.  See the Wiki

http://wiki.freeradius.org

Read the configuration files.  Many parts of the server have NO
documentation, other than comments in the configuration file.

Search the mailing lists.  There is a Google link on the bottom of
the page:

http://www.freeradius.org/list/users.html

Type some key words into the search box, and you should find
discussions about common problems and solution.


Feedback, Defects, and Community Support
----------------------------------------

If you have any comments, or are having difficulty getting FreeRADIUS
to do what you want, please post to the 'freeradius-users' list
(see the URL above).  The FreeRADIUS mailing list is operated and
contributed to, by the FreeRADIUS community. Users of the list will be
more than happy to answer your questions, with the caveat that you've
read documentation relevant to your issue first.

If you suspect a defect in the server, would like to request a feature,
or submit a code patch, please use the GitHub issue tracker for the
freeradius-server `repository
<https://github.com/FreeRADIUS/freeradius-server>`_.

Instructions for gathering data for defect reports can be found in
``doc/bugs`` or on the `wiki
<http://wiki.freeradius.org/project/bug-reports>`_.

Under no circumstances should the issue tracker be used for support
requests, those questions belong on the user's mailing list.  If you
post questions related to the server in the issue tracker, the issue
will be closed and locked.  If you persist in positing questions to
the issue tracker you will be banned from all FreeRADIUS project
repositories on GitHub.

Please do NOT complain that the developers aren't answering your
questions quickly enough, or aren't fixing the problems quickly
enough.  Please do NOT complain if you're told to go read
documentation.  We recognize that the documentation isn't perfect, but
it *does* exist, and reading it can solve most common questions.

FreeRADIUS is the cumulative effort of many years of work by many
people, and you've gotten it for free.  No one is getting paid to answer
your questions.  This is free software, and the only way it gets better
is if you make a contribution back to the project ($$, code, or
documentation).

We will note that the people who get most upset about any answers to
their questions usually do not have any intention of contributing to
the project.  We will repeat the comments above: no one is getting
paid to answer your questions or to fix your bugs.  If you don't like
the responses you are getting, then fix the bug yourself, or pay
someone to address your concerns.  Either way, make sure that any fix
is contributed back to the project so that no one else runs into the
same issue.

Books on RADIUS
---------------

See ``doc/README`` for more information about FreeRADIUS.

There is an O'Reilly book available.  It serves as a good
introduction for anyone new to RADIUS.  However, it is almost 12 years
old, and is not much more than a basic introduction to the subject.

http://www.amazon.com/exec/obidos/ASIN/0596003226/freeradiusorg-20/

Commercial support
------------------

Technical support, managed systems support, custom deployments,
sponsored feature development and many other commercial services
are available from `Network RADIUS
<http://www.networkradius.com>`_.


.. |CoverityStatus| image:: https://scan.coverity.com/projects/58/badge.svg?
.. _CoverityStatus: https://scan.coverity.com/projects/58

.. |BuildStatus| image:: https://travis-ci.org/FreeRADIUS/freeradius-server.png?branch=v3.1.x
.. _BuildStatus: https://travis-ci.org/FreeRADIUS/freeradius-server
