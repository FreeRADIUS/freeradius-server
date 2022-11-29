# rlm_unix
## Metadata
<dl>
  <dt>category</dt><dd>datastore</dd>
</dl>

## Summary

Retrieves a user's encrypted password from the local system and
places it into the `&control:Crypt-Password` attribute. The
password is retrieved via the `getpwent()` and `getspwent()`
system calls.

When used for accounting, works in conjunction with rlm_radutmp to
update the utmp database.
