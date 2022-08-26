#  This needs to be cleared explicitly, as the libfreeradius-ldap.mk
#  might not always be available, and the TARGETNAME from the previous
#  target may stick around.
TARGETNAME=
-include $(top_builddir)/src/lib/ldap/all.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= sync_touch
  TARGET	:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c
TGT_PREREQS	:= libfreeradius-ldap$(L)
