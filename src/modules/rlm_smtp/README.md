# rlm_smtp
## Metadata
<dl>
  <dt>category</dt><dd>authorization</dd>
</dl>

## Summary
Allows users to submit smtp formatted, mime-encoded emails to a server
Supports User-Name User-Password authentication
Supports file attachments, size limited by the MDA

Required request elements:
SMTP-Sender-Email
SMTP-Recipients
SMTP-Mail-Header
SMTP-Mail-Body

Optional request elements:
SMTP-Attachments
User-Name
User-Password
