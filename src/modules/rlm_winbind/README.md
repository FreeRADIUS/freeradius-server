# rlm_winbind
## Metadata
<dl>
  <dt>category</dt><dd>authentication</dd>
</dl>

## Summary
The module also allows for direct connection to Samba winbindd (version 4.2.1 or above), which communicates with
Active-Directory to retrieve group information and the user's NT-Password.

The legacy ntlm_auth utility is also supported, but this comes with an approximate 30% performance penalty.

