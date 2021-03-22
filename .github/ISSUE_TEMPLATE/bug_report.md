---
name: Bug Report
about: Used to report a defect in server source code, default configuration files, documentation, scripts etc...  Post questions about usage to the user's mailing list (http://freeradius.org/support/).
---

# Issue type
- **Questions about the server or its usage MUST be posted to the [users mailing list](http://freeradius.org/list/users.html).  If you post those issues here, they will be closed and locked. Repeat offenders will be BANNED**.
- **Remote security exploits MUST be sent to security@freeradius.org.**

***

**REMOVE THOSE WHICH DO NOT APPLY**
- Defect - Crash or memory corruption.
- Defect - Non compliance with a standards document, or incorrect API usage.
- Defect - Unexpected behaviour (obvious or verified by project member).

See [here](https://github.com/FreeRADIUS/freeradius-server/blob/master/doc/source/bugs.md) for debugging instructions and how to obtain backtraces.

## Defect

### How to reproduce the issue

A clear and concise list of steps describing how to describe the issue.

### Output of ``[radiusd|freeradius] -X`` showing issue occurring
_(you may need to run ``[radiusd|freeradius] -fxx -l stdout`` if using eg RADIUS with TLS)_

```text
COPY/PASTE OUTPUT HERE (WITHIN BACKTICKS).  NO PASTEBIN (ET AL) LINKS!
```
### Full backtrace from LLDB or GDB

```text
COPY/PASTE OUTPUT HERE (WITHIN BACKTICKS).  NO PASTEBIN (ET AL) LINKS!
```
