TARGETNAME=
-include $(top_builddir)/src/lib/ldap/all.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= proto_ldap_sync_ldap
  TARGET	:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_ldap_sync_ldap.c rfc4533.c persistent_search.c active_directory.c

TGT_PREREQS	:= proto_ldap_sync$(L) libfreeradius-ldap$(L) libfreeradius-internal$(L)
