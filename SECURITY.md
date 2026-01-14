# Security Policy

All security vulnerabilities should be reported to security@freeradius.org

All security disclosures are published on the FreeRADIUS web site, at https://www.freeradius.org/security/

## Supported Versions

We accept security reports for version 3.0, 3.2, and for the git
"master" branch, as seen in the table below.

| Version    | Supported          | 
| ---------- | ------------------ |
| "master"   | :white_check_mark: |
| 3.2.x      | :white_check_mark: |
| 3.0.x      | :white_check_mark: |
| < 3.0      | :x:                |

### Git "master" branch.

We accept security reports for the "master" branch.  However, please
be aware that while this branch will eventually become version 4.0.0,
we have not yet made an official release.

The "master" branch may have temporary issues as development
continues.  The "master" branch may even have compile failures from
time to time.

### Version 3.2.x

Version 3.2 is the currently supported release stream.  We accept
security reports, feature requests, bug reports, etc. for this branch.

### Version 3.0.x

Version 3.0 is the current "stable" release stream.  It is officially
"end of life", and no further development is being done on that
branch.

We accept security reports for this branch, but we do not accept
feature requests or bug reports, for this branch.

### Versions before 3.0

We do not accept security notifications for versions before 3.0.

All older versions of FreeRADIUS are officially not just "end of
life", but are "end of support".  No code changes will be made to
those versions, even for security vulnerabilities.

## Reporting a Vulnerability

All security vulnerabilities should be reported to security@freeradius.org

### PGP Key

The following PGP key can be used to sign messages which are sent to
security@freeradius.org.  The key is also available on PGP key servers
(for aland@freeradius.org), and on the FreeRADIUS web site at
https://www.freeradius.org/pgp/aland@freeradius.org


-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.0.6 (GNU/Linux)
Comment: For info see http://www.gnupg.org

mQCNAzx7wFMAAAEEALq2yahNGENq7Z8xqIaaxlMYPEqdnWme+QQRobX+0mHJ+xjv
uU9icVaQJrgrcgmH9Sx5avAZViypk/bBSwxUxbUZfF9LRsEPJB2Rpg2eLuxShYiE
x0CMCAIQvDFCmygm4+dqgkj1/BCImki8nvQIoW56uTTkskZuq6kul4vkAkl9AAUR
tCRBbGFuIFQuIERlS29rIDxhbGFuZEBmcmVlcmFkaXVzLm9yZz6JAJUDBRA8e8BT
qS6Xi+QCSX0BAXvOA/wPxVKQXtyfQSFi8WrPa0QUaRzm8j9Kna9u9Xn2wzF18neH
ogxzDIdJZtB2zDRKaRbNeYrcz0LnC5sxZqMco0NkI7P2ifE42aWXauSuYaYA9uG6
kP+CFjprorK0Cc6NUL47nWxB5x5zkix85MUjkMbOFyrZrUKKcHAeWfjzMf0Vkg==
=VwDM
-----END PGP PUBLIC KEY BLOCK-----
