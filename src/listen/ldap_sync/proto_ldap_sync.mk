TARGETNAME=
-include $(top_builddir)/src/lib/ldap/all.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= proto_ldap_sync
  TARGET	:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_ldap_sync.c

TGT_PREREQS	:= libfreeradius-io$(L) libfreeradius-ldap$(L) libfreeradius-internal$(L)
