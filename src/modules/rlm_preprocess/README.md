# rlm_preprocess
## Metadata
<dl>
  <dt>category</dt><dd>policy</dd>
</dl>

## Summary
Preprocesses the incoming request before handing it off to other modules.

Supports the legacy huntgroups and hints files. In addition, it re-writes some unusual attributes created by some
NASes and converts the attributes into a form that is a little more standard.

This module is mostly deprecated in favour of unlang, but is kept in current distributions to provide backwards
compatibility.
