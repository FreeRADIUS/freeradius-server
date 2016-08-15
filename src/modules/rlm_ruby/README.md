# rlm_ruby
## Metadata
<dl>
  <dt>category</dt><dd>languages</dd>
</dl>

## Summary
Allows the server to call a persistent, embedded Ruby script.

Unfortunately Ruby was not designed for embedding, and this module has resource utilisation issues.  If you really must
use this module, it's recommended to periodically restart FreeRADIUS to clean up any leaked memory.
