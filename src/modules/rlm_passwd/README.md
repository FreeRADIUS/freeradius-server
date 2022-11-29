# rlm_passwd
## Metadata
<dl>
  <dt>category</dt><dd>datastore</dd>
</dl>

## Summary

Reads and caches line-oriented files that are in a format similar
to `/etc/passwd`.

It assumes that each line is composed of a series of records,
separated by a delimiter. The records are read from the file,
cached, then retrieved during request processing and inserted into
the request.
