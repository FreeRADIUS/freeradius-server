# rlm_ldap_otp
## Metadata
<dl>
  <dt>category</dt><dd>datastore</dd>
  <dt>category</dt><dd>authentication</dd>
</dl>

## Summary
Provides multi-factor authentication by combining LDAP password validation with local OTP (TOTP/HOTP) verification.

OTP secrets are stored locally in SQL databases (MySQL, PostgreSQL, SQLite) with AES-256-CBC encryption, eliminating
the need for external OTP validation servers.

Supports RFC 6238 (TOTP) and RFC 4226 (HOTP) with standard authenticator applications.
