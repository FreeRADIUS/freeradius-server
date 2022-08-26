TARGETNAME=
-include $(top_builddir)/src/lib/ldap/all.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= proto_ldap_sync
  TARGET	:= $(TARGETNAME).a
endif

SOURCES		:= proto_ldap_sync.c

TGT_PREREQS	:= libfreeradius-io.a libfreeradius-ldap.a libfreeradius-internal.a
