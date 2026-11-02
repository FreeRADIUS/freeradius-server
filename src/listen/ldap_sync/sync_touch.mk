#  This needs to be cleared explicitly, as the libfreeradius-ldap.mk
#  might not always be available, and the TARGETNAME from the previous
#  target may stick around.
TARGETNAME=
-include $(top_builddir)/src/lib/ldap/all.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= sync_touch
  TARGET	:= $(TARGETNAME)$(E)
endif
TGT_CATEGORY	:=

#
#  A testing tool, so it isn't installed.
#
TGT_INSTALLDIR	:=

SOURCES		:= $(TARGETNAME).c

#
#  Only uses libldap.  The include of src/lib/ldap/all.mk above provides
#  the libldap build and link flags.
#
TGT_PREREQS	:=
