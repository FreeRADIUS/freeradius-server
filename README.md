# The FreeRADIUS server

[![Travis CI build status][BuildStatus]][BuildStatusLink] [![Coverity Status][CoverityStatus]][CoverityStatusLink] [![LGTM Status][LGTMStatus]][LGTMStatusLink]

## Introduction

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

## Documentation

Please see the [documentation](doc/) directory, which has full
documentation for version 4.

Please also see https://freeradius.org and https://wiki.freeradius.org
for additional documentation.

## Installation

To install the server, please see the [installation
instructions](doc/howto/INSTALL.adoc) document.

## Configuring the server

We understand that the server may be difficult to configure,
install, or administer.  It is, after all, a complex system with many
different configuration possibilities.

The most common problem is that people change large amounts of the
configuration without understanding what they're doing, and without
testing their changes.  The preferred method of operation is the
following:

1. Start off with the default configuration files.
2. Save a copy of the default configuration: It WORKS.  Don't change it!
3. Verify that the server starts - in debugging mode (`radiusd -X`).
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

## Debugging the Server

Run the server in debugging mode, (`radiusd -X`) and READ the output.
We cannot emphasize this point strongly enough.  The vast majority of
problems can be solved by carefully reading the debugging output,
which includes WARNINGs about common issues, and suggestions for how
they may be fixed.

The debug output is explained in detail in the
[radiusd-X](http://wiki.freeradius.org/radiusd-X) page on the
[wiki](http://wiki.freeradius.org).

Many questions are answered on the Wiki:

https://wiki.freeradius.org

Read the configuration files.  Many parts of the server are
documented only with extensive comments in the configuration files.

Search the mailing lists. For example, using Google, searching
"site:lists.freeradius.org <search term>" will return results from
the FreeRADIUS mailing lists.

https://freeradius.org/support/

Instructions for what to post on the mailing list are [on the
wiki](http://wiki.freeradius.org/list-help).  Please note that we DO
recommend posting the output of `radiusd -X`.  We do NOT recommend
posting the configuration files.

## Feedback, Defects, and Community Support

If you have any comments, or are having difficulty getting FreeRADIUS
to do what you want, please post to the 'freeradius-users' list (see
the URL above). The FreeRADIUS mailing list is operated, and
contributed to, by the FreeRADIUS community. Users of the list will be
more than happy to answer your questions, with the caveat that you
have read the documentation relevant to your issue first.

If you suspect a defect in the server, would like to request a feature,
or submit a code patch, please use the GitHub issue tracker for the
freeradius-server
[repository](https://github.com/FreeRADIUS/freeradius-server).
However, it is nearly always best to raise the issue on the
mailing lists first to determine whether it really is a defect or
missing feature.

Instructions for gathering data for defect reports can be found in
`doc/developers/bugs.adoc` or on the [wiki](https://wiki.freeradius.org/project/bug-reports).

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
people, and you have gotten it for free.  No one is getting paid to
answer your questions.  This is free software, and the only way it
gets better is if you make a contribution back to the project ($$,
code, or documentation).

## Commercial support

Technical support, managed systems support, custom deployments,
sponsored feature development and many other commercial services
are available from [Network RADIUS](https://networkradius.com).

[CoverityStatus]: https://scan.coverity.com/projects/58/badge.svg?flat=1 "Coverity Status"
[CoverityStatusLink]: https://scan.coverity.com/projects/58
[BuildStatus]: https://travis-ci.org/FreeRADIUS/freeradius-server.png?branch=master "Travis CI status"
[BuildStatusLink]: https://travis-ci.org/FreeRADIUS/freeradius-server
[LGTMStatus]: https://img.shields.io/lgtm/alerts/g/FreeRADIUS/freeradius-server.svg?logo=lgtm&logoWidth=18
[LGTMStatusLink]: https://lgtm.com/projects/g/FreeRADIUS/freeradius-server/alerts/
