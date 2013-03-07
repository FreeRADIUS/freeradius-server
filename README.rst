The FreeRADIUS server
=====================

0. BRANCH STATE
---------------
|BuildStatus|_

.. |BuildStatus| image:: https://travis-ci.org/FreeRADIUS/freeradius-server.png?branch=v2.x.x
.. _BuildStatus: https://travis-ci.org/FreeRADIUS/freeradius-server

1. INTRODUCTION
---------------

The FreeRADIUS Server Project is a high performance and highly
configurable AAA server.  Is available under the terms of the GNU
GPLv2.  It has been in steady development for over a decade.  It is
the most widely used RADIUS server in the world, by quite a large
margin.

AAA stands for "Authentication, Authorization, and Accounting".  The
server can do any or all of the AAA functions, across three protocols:
RADIUS, DHCP, and VMPS.  The reason is that at its core, it is a
policy engine.  The policy engine connects network protocols to
back-end systems such as SQL, LDAP, Active Directory, etc.

FreeRADIUS started out as a RADIUS server, of course.  We then added
VMPS and DHCP when it became clear that doing so was both easy and
useful.

It supports all popular authentication methods for RADIUS.  This
includes PAP, CHAP, MS-CHAP, EAP, etc.  It works with all known
networking equipment.  The authors of FreeRADIUS have written the
official specifications for how RADIUS works (RFC 5080 and RFC 6158,
among others).  It is compliant with all RADIUS standards.  This means
that if a NAS does not inter-operate with FreeRADIUS, the most likely
reason is that the NAS is wrong.

FreeRADIUS can authenticate users on systems such as 802.1x (WiFi),
dialup, PPPoE, VPN's, VoIP, and many others.  It supports back-end
databases such as MySQL, PostgreSQL, Oracle, Microsoft Active
Directory, OpenLDAP, and many more.  It is used daily to authenticate
the Internet access for hundreds of millions of people, in sites
ranging from 10 users, to 10 million and more users.  It is used in
appliances, WiFi boxes, ISPs, enterprises, and large
telecommunications providers.

Version 2.2 of the server is intended to be backwards compatible with
previous versions.  It has features not available in Version 1, many
of which are also not available in any commercial server.

* simple policy language (see ``man unlang``)
* virtual servers (raddb/sites-available/README)
* DHCP support (server and relay)
* VMPS support
* IPv6 support
* better proxy support (raddb/proxy.conf)
* More EAP types
* verbose and descriptive Debugging output
* Almost 50 "stable" modules, and many more experimental ones.
* Sample SQL configuration for all major SQL databases.
* Some support for on-the-fly changing of configuration (HUP)
* check configuration test (``radiusd -C``)
* Event-based server core.

Please see http://freeradius.org and http://wiki.freeradius.org for
more information.


2. INSTALLATION
---------------

To install the server, please see the INSTALL file in this directory.
In general, we recommend using a pre-packaged installation for your
operating system.


3. DEBUGGING THE SERVER
-----------------------

RADIUS systems can be complicated to configure.  Unlike a simple
"query-response" protocol such as DNS, RADIUS systems need to juggle
large amounts of information.  There may be dozens of attributes in
the request.  Processing the request may involve querying any or all
of LDAP, SQL, flat files, external scripts, etc.

There is no easy solution to creating a working RADIUS configuration.
The only method that works is to run the server in debugging mode,
(``radiusd -X``) and READ the output.  We cannot emphasize this point
strongly enough.  The vast majority of problems can be solved by
carefully reading the debugging output, which includes WARNINGs about
common issues, and suggestions for how they may be fixed.

Read the FAQ.  Many questions are answered there.  See the Wiki

http://wiki.freeradius.org

Read the configuration files.  Many parts of the server have NO
documentation, other than comments in the configuration file.  That
being said, there are dozens of examples in the configuration files.
The configuration items are extensively commented, with all of their
behavior documented.

Search the mailing lists.  Many questions come up repeatedly, and are
answered there.  There is a Google link on the bottom of the page:

http://www.freeradius.org/list/users.html

Type some key words into the search box, and you should find
discussions about common problems and solution.


4. ADDITIONAL INFORMATION
-------------------------

See 'doc/README' for more information about FreeRADIUS.

See raddb/sites-available/README for documentation on virtual servers.

5. PROBLEMS AND CONCERNS
------------------------

We understand that the server may be difficult to configure,
install, or administer.  It is, after all, a complex system with many
different configuration possibilities.

The most common problem is that people change large amounts of the
configuration without understanding what they're doing, and without
testing their changes.  The preferred method of operation is the
following:

1. Start off with the default configuration files.
2. Save a copy of the default configuration: It WORKS.  Don't change it!
3. Run the server in debugging mode. (radiusd -X)
4. Send it test packets using "radclient", or a NAS or AP.
5. Verify that the server does what you expect.
      - If it does not work, change the configuration, and go to step (3) 
        If you're stuck, revert to using the "last working" configuration.
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


6. FEEDBACK
-----------

If you have any comments, bug reports, problems, or concerns, please
send them to the 'freeradius-users' list (see the URL above).  We will
do our best to answer your questions, to fix the problems, and to
generally improve the server in any way we can.

Please do NOT complain that the developers aren't answering your
questions quickly enough, or aren't fixing the problems quickly
enough.  Please do NOT complain if you're told to go read
documentation.  We recognize that the documentation isn't perfect, but
it *does* exist, and reading it can solve most common questions.

The list policy changed in mid 2012, due to the high volume of
inappropriate posts from a subset of users.  These users would refuse
to read the documentation, even when asked to.  They would ask
questions, and then refuse to follow the instructions given them on
the list.  They would argue over the answers given on the list, even
when it was clear that they understood less about RADIUS than the
people trying to help them.

The new policy is to warn people engaging in this asocial behavior.
If they continue after a warning, they are unsubscribed and banned
permanently from the list.

The decision to enforce etiquette came after over 10 years of having a
more open policy.  Sadly, a small subset of users abused the help
given by the volunteers on the list.  This behavior is unacceptable,
and will not be tolerated.

FreeRADIUS is the cumulative effort of many years of work by many
people, and you've gotten it for free.  No one gets paid to work on
FreeRADIUS, and no one is getting paid to answer your questions.

If you want the community to help you, you need to make it easy for
the community to help you.

Support is available.  See http://networkradius.com/.

Please submit bug reports, suggestions, or patches.  That feedback
gives the developers a guide as to where they should focus their work.
If you like the server, feel free to mail the list and say so.
