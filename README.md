# The FreeRADIUS server

[![CI build status](https://github.com/FreeRADIUS/freeradius-server/actions/workflows/ci.yml/badge.svg)][BuildStatusLink] [![Coverity status][CoverityStatus]][CoverityStatusLink] [![OSS-Fuzz status][OssFuzz]][OssFuzzLink]

## Introduction

The FreeRADIUS Server Project is a high performance and highly
configurable multi-protocol policy server, supporting RADIUS, DHCPv4
DHCPv6, DNS, TACACS+ and VMPS. It is available under the terms of the GNU GPLv2.
Using RADIUS allows authentication and authorization for a network
to be centralized, and minimizes the number of changes that have to
be done when adding or deleting new users to a network.

FreeRADIUS can authenticate users on systems such as 802.1x (WiFi),
dialup, PPPoE, VPN's, VoIP, and many others.  It supports back-end
databases such as MySQL, MariaDB, PostgreSQL, Oracle, Microsoft Active
Directory, Apache Cassandra, Redis, OpenLDAP, and many more.  It is
used daily to authenticate the Internet access for hundreds of millions
of people, in sites ranging from 10 to 10 million+ users.

## WARNING

VERSION 4 IS IN DEVELOPMENT AND HAS NOT BEEN OFFICIALLY RELEASED. USE AT YOUR OWN RISK.

Please wait for an official release before using version 4 (v4).

## Documentation

Please see the [documentation](doc/) directory, which has full
documentation for version 4.

Please also see <https://freeradius.org> and <https://www.freeradius.org/documentation/freeradius-server/4.0.0/>
for additional documentation.

### AI-assisted tools

AI-assisted tools can help draft configurations, explain existing files,
review changes, and explore implementation options. Their output is not
automatically correct or compatible with the intended FreeRADIUS version.
Generated examples may contain unsupported attributes, mistaken syntax,
or unsuitable authentication and security settings.

Treat generated output as a proposal requiring review. Check it against
the version-specific documentation and configuration examples, and test
changes in an appropriate environment before deploying them. Do not
include credentials or other secrets in external tool inputs.

Contributions prepared with automation are evaluated using the same
technical and verification standards as other submissions; see the
[contribution guide](.github/contributing.md). Coding agents can find
repository-specific navigation and verification guidance in
[AGENTS.md](AGENTS.md).

## Installation

To install the server, please see the [installation
instructions](doc/antora/modules/howto/pages/installation/index.adoc) document.

## Configuring the server

We understand that the server may be difficult to configure,
install, or administer.  It is, after all, a complex system with many
different configuration possibilities.

Changing many settings at once can make an error difficult to isolate.
A repeatable configuration workflow is:

1. Start off with the default configuration files.
2. Save a copy of the default configuration before editing it.
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

Incremental testing helps isolate regressions and provides a record of
working configurations and the changes made between them.

## Debugging the Server

For configuration troubleshooting, run a test instance with the changed
configuration using `radiusd -X`, and inspect startup errors and the trace
for a specific test request. Do not interrupt a live production instance
solely to collect console diagnostics. For a running server, use `raddebug`
when a control socket is configured.

The debug output is explained in detail in the
[radiusd-X](https://www.freeradius.org/documentation/freeradius-server/4.0.0/debugging/radiusd_X.html)
page.

Read the configuration files.  Many parts of the server are
documented only with extensive comments in the configuration files.

Search the mailing lists. For example, using Google, searching
"site:lists.freeradius.org <search term>" will return results from
the FreeRADIUS mailing lists.

[Additional
help](https://www.freeradius.org/documentation/freeradius-server/4.0.0/gethelp.html)
is available via the mailing lists, including commercial support.

When asking for help with a runtime problem, provide the FreeRADIUS
version, the configuration change, an example request, its actual response
or error, and the corresponding `radiusd -X` trace. If the server cannot
start, include the startup error and relevant service log instead.

Check diagnostics for sensitive data before publishing them. Built-in
redaction cannot guarantee that external programs or custom logging omit
credentials. Supply configuration excerpts only when they are necessary
to reproduce a specific problem, and remove credentials before sharing.

## Feedback, Defects, and Community Support

For configuration and operational questions, use the 'freeradius-users'
mailing list. Include the version, exact steps or test request, the reply
or error you observed, and the corresponding diagnostic output.

If you suspect a defect in the server, would like to request a feature,
or submit a code patch, please use the GitHub issue tracker for the
freeradius-server
[repository](https://github.com/FreeRADIUS/freeradius-server).
However, it is nearly always best to raise the issue on the
mailing lists first to determine whether it really is a defect or
missing feature.

Instructions for gathering data for defect reports can be found in
[here](doc/antora/modules/developers/pages/bugs/bugs.adoc) and online at
<https://www.freeradius.org/documentation/freeradius-server/4.0.0/developers/bugs.html>

Use GitHub issues for reproducible software and documentation defects
and feature requests. Configuration and operational support questions
belong on the users mailing list; issues filed through the wrong channel
may be redirected or closed. See the contribution guidelines for details.

Community support is provided by volunteers, so response times can vary.
FreeRADIUS is maintained through contributions of code, documentation,
testing, and funding.

## Commercial support

Technical support, managed systems support, custom deployments,
sponsored feature development and many other commercial services
are available from [InkBridge Networks](https://www.inkbridgenetworks.com).

[BuildStatus]: https://github.com/FreeRADIUS/freeradius-server/workflows/CI/badge.svg?branch=master "CI status"
[BuildStatusLink]: https://github.com/FreeRADIUS/freeradius-server/actions?query=workflow%3ACI
[OssFuzz]: https://oss-fuzz-build-logs.storage.googleapis.com/badges/freeradius.svg "OSS-Fuzz status"
[OssFuzzLink]: https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:freeradius
[CoverityStatus]: https://scan.coverity.com/projects/58/badge.svg?flat=1 "Coverity Status"
[CoverityStatusLink]: https://scan.coverity.com/projects/58
[LGTMStatus]: https://img.shields.io/lgtm/alerts/g/FreeRADIUS/freeradius-server.svg?logo=lgtm&logoWidth=18
[LGTMStatusLink]: https://lgtm.com/projects/g/FreeRADIUS/freeradius-server/alerts/
