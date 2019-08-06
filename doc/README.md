= FreeRADIUS Documentation

This is the documentation for FreeRADIUS, version 4.  The
documentation is available under the Creative Commons Non-Commercial
license, as given in the `LICENSE` file in this directory.

FreeRADIUS is a complex piece of software with many configuration
options.  However, we have taken great care to make the default
configuration work in most circumstances.  The result is that for most
simple systems, it is trivial to install and configure the server.
For those situations, this documentation will serve to answer basic
questions about functionality, configuration, etc.

For more complex requirements, FreeRADIUS can be extremely difficult
to configure.  The reason for this difficulty is that the server can
do almost anything, which means that there are near-infinite ways to
configure it.  The question for an administrator, then, is which piece
of the configuration to change, and how to change it.

This documentation will answer those questions.  The FreeRADIUS team
has put substantial effort into writing the documentation for this
release.  Everything in the server is fully documented, and there are
many "how-to" guides available.

The documentation is split into sections by subject area, oganized by
desired outcome.  At a high level, the subject areas describe:

* concepts and [introduction](introduction/) for newcomers,
* the syntax of the [unlang](unlang/) processing language,
* the [configuration files](raddb/),
* various [how-to](howto/) guides,
* [upgrading](upgrade/) from a previous version of FreeRADIUS,
* and [developer documentation](source/)

 This organization means that for example, the `ldap` module will have
 documention located in multiple places.  We feel that organizing the
 documentation by desired "goal" is better than the alternatives.

Within each section, the documentation is split into small pages,
which are generally no more than a few screens worth of information.
We feel that having multiple small pages with cross-links is more
helpful than having a smaller number of enormous pages.  This division
ensures that (for example) the "how-to" guides are split into a series
of small steps, each of which can be performed quickly.

The documentation here is substantially more complete and in-depth
than in any previous version of the server.  We hope that this level
of detail will address any lingering concerns about the quality of the
FreeRADIUS documentation.

## Getting Started

We recommend installing FreeRADIUS from the pre-built packages
available at [Network RADIUS](http://packages.networkradius.com).
Many Operating System distributions ship versions of FreeRADIUS which
are years out of date.  The page given above contains recent packages
for all common OS distributions.  For historical purposes, packages of
older releases are also available.

Administrators who are new to FreeRADIUS should read the
[introduction](introduction/) documentation.  That section describes
the concepts behind FreeRADIUS.  It is vital for newcomers to
understand these concepts, as the rest of the documentation assumes
familiarity with them.

Administrators who have version 3 and wish to upgrade to version 4
should read the [upgrading](upgrade/) documentatin.  That section
explains the differences between the two versions, and how an existing
configuration can be reproduced in the latest release.

A detailed [Unlang Reference](unlang/) guide is also available.  This
section describes the syntax and functionality of the keywords, data
types, etc. used in the "unlang" processing language.

All of the [configuration files](raddb/) are available in hypertext
format.  In can often be easier to read the configuration files in a
nicely formatted version, instead of as a fixed-width font in a text
editor.

For specific problem solving, we recommend the [how-to](howto/)
guides.  These guides give instructions for reaching high-level goals,
or for configuring and testing individual [modules](howto/modules/).

There is also [developer documentation](source/).  This section
documents the APIs for developers.  Most people can ignore it.

## Debugging

If you have ANY problems, concerns, or surprises when running
the server, then run it in debugging mode, as root, from the
command line:

    # radiusd -X

It will produce a large number of messages.  The answers to many
questions, and the solution to many problems, can usually be found in
these messages.  When running in a terminal window, error messages
will be shown in red text, and warning messages will be shown in
yellow text.

For other use-cases, please look for `ERROR` or `WARNING` in the debug
output.  In many cases, those messages describe exactly what is going
wrong, and how to fix it.

For further details, about the debug output see the
[radiusd-X](http://wiki.freeradius.org/radiusd-X) page on the
[wiki](http://wiki.freeradius.org).

## Getting Help

We also recommend joining the [mailing
list](http://lists.freeradius.org/mailman/listinfo/freeradius-users)
in order to ask questions and receive ansswers.  The developers are
not on Stack Overflow, IRC, or other web sites.  While the FreeRADIUS
source is available on
[GitHub](https://github.com/FreeRADIUS/freeradius-server/), questions
posted there will not be answered.

WARNING: Posting questions to the mailing list *without* including the
debug output is generally not acceptable.  Doing so will usually cause
the developers to reply, saying "post the debug output".

We simply cannot emphasize enough the importance of running the server
in debugging mode, and _reading_ the output.
