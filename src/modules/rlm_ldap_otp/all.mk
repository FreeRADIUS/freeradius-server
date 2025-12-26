TARGET := rlm_ldap_otp$(L)

SOURCES := rlm_ldap_otp.c

TGT_PREREQS := libfreeradius-util$(L) libfreeradius-server$(L) libfreeradius-totp$(L)
