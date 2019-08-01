= Ascend Radius Options

What happens when a big vendor ignores an RFC

## Description

FreeRADIUS uses Vendor-Specific attributes to send the Ascend attributes.
By default, Ascend NASes send the Ascend specific attributes as NON VSA's,
which conflict with new RADIUS attributes assigned by the IETF.  This was
a very bad screw-up by Ascend that still causes many headaches, but sometimes
we have to live with it, so we try to cope the best we can.

If you see a large number of messages about invalid Message-Authenticator
attribute, you most likely are affected by this problem, and should implement
the first option.

You have two options:

### Option 1: Enable VSA's on the Ascend/Lucent MAX

This is by far the preferred method (as it solves many other problems).

Max6000/4000 Series TAOS with Menued Interface:

  1. Go to Ethernet->Mod Config->Auth.
  2. At the bottom of the menu, change Auth-Compat from `OLD` to `VSA`.
  3. Save your changes, no reboot is needed.

  1. Go to Ethernet->Mod Config->Acct.
  2. At the bottom of the menu, change Acct-Compat from `OLD` to `VSA`.
  3. Save your changes, no reboot is needed.

Max TNT/Apex 8000 Series TAOS with CLI:

    nas> read external-auth
    nas> set rad-auth-client auth-radius-compat = vendor-specific
    nas> set rad-acct-client acct-radius-compat = vendor-specific
    nas> write

### Option 2: Enable OLD attributes in FreeRADIUS

  One note on this, Ciscos have an Ascend compatibility mode that
  accepts only the OLD style Ascend attributes, just to make life more
  interesting.  :)

  You can make FreeRADIUS send the OLD style attributes by prefixing the
  Ascend attributes with 'X-' in the 'users' file, sql table, ldap directory,
  attr_filter module, etc...

  Thus the VSA Ascend attribute:

     Ascend-Data-Filter

  becomes the OLD Ascend attribute:

     X-Ascend-Data-Filter
