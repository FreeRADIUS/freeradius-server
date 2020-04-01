# rlm_imap
## Metadata
<dl>
  <dt>category</dt><dd>authentication</dd>
</dl>

## Summary
### This is a module that sends an authorization-request message to an imap server.
### The module then returns either:
##### RLM_MODULE_NOOP - not enough information to send connection request
##### RLM_MODULE_OK - Connection request was acceped by imap server
##### RLM_MODULE_REJECT - Connection request failed for any reason
