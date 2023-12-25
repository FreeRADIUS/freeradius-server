# Contributing

## Introduction

The FreeRADIUS project wouldn't exist without contributions from a significant number of developers.

We greatly value all comments, defect reports, patches/pull-requests, but must balance individual
contributor's desires and practices against what's required for the project to operate efficiently.

This document describes best practices when interacting with members of the FreeRADIUS project team
via GitHub.  If you follow these guidelines, it is very likely that your bug report or pull request will
be acted on and in a timely manner.

If you choose to ignore these guidelines our response will be a link to this document.


## GitHub Issue Tracker

The GitHub issue tracker is for non-security related defect reports, feature requests, and
pull-requests ONLY.

It is not for support requests or questions regarding configuration/operation of the server, they
belong on the [users mailing list](https://freeradius.org/support/).

Raising support requests or questions as issues will result in them being closed and locked.  If you
continue to raise these questions as issues you will be banned from the FreeRADIUS project's GitHub
repositories.

Security issues should be reported to security@freeradius.org especially if they can be remotely
exploited.  This ensures that patches can be developed before the exploit is made public.


## Defect reporting

### Before reporting a defect

Verify it's still present in the Git HEAD.  Checkout the appropriate branch for the version of the
server you're working with, as listed [here](https://doc.freeradius.org), build the server and attempt
to reproduce your issue.

The [ChangeLog](https://github.com/FreeRADIUS/freeradius-server/blob/v3.0.x/doc/ChangeLog) for the
current stable branch may also be used to determine if your issue has already been addressed.
The ChangeLog is updated as fixes are made to the server code, and usually reflects the state of the
Git HEAD.

Do not report non-security defects for EOL branches (as listed on doc.freeradius.org), or old releases.
Issues reported for these branches will be closed and locked.

### Contents of a defect report

See [doc/bugs](https://github.com/FreeRADIUS/freeradius-server/blob/master/doc/source/bugs.md) for information
on what to include, and how to obtain it.

When logging bug reports using the GitHub issue tracker, pay attention to formatting.  You should
ensure any log output is surrounded by two sets of triple backticks (```).  If you don't do this
GitHub will automatically link your issue to other pre-existing issues when it encounters a ``#<num>``
string.


## Pull requests and coding standards

If you're developing a new feature, module, or writing large amounts of code to fix a defect, contact
a member of the FreeRADIUS development team first.  For simpler one or two line fixes go ahead and
open a pull-request immediately.

The dev team can be contacted via the [devel mailing list](https://freeradius.org/support/),
or via GitHub by using the GitHub issue tracker.

Contacting the dev team gives us the opportunity to offer feedback.  We may have a solution to your
problem that doesn't require additional code, or may have ideas as to how your problem can be solved
in a way that will better fit with the long-term vision for the server.

Once you've got the go ahead, please read through the
[coding standards document](https://wiki.freeradius.org/contributing/coding-standards).

If you're creating a new module you may wish to read the
[module creation guide](https://wiki.freeradius.org/contributing/Modules3).

You may also wish to utilise the [doxygen site](https://doc.freeradius.org) to review code documentation.

The doxygen site contains the complete reference of all API functions with doxygen headers as well
as structs and callback declarations.  <https://doc.freeradius.org> is updated within one minute of each
commit to the master branch of the freeradius-server repository.

Finally, this file was written to be displayed automatically on the GitHub issue tracker, so
Git/GitHub knowledge is assumed.  If you're wondering what a pull-request is, this document may be of
some use <https://wiki.freeradius.org/contributing/GitHub>.


## Continuous Integration Tests (CIT)

If possible include test cases in your pull-requests.

There are currently three test frameworks for different elements of the server:

| Type         | Path                   | Description                                          |
|--------------|------------------------|------------------------------------------------------|
| Unit tests   | `src/tests/unit/*.txt` | Tests for conditions and protocol encoders/decoders. |
| Module tests | `src/tests/modules/`   | Tests for module functionality.                      |
| Unlang tests | `src/tests/unlang/`    | Tests for unlang keywords and functions.             |

See `README.*` docs in the directories above for basic information on writing test cases.  The easiest
way to write new tests is to use the existing tests as examples.

Tests are run via Travis for each pull-request, and on every commit by a developer with repository
access.
