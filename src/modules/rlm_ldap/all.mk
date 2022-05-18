#  This needs to be cleared explicitly, as the libfreeradius-ldap.mk
#  might not always be available, and the TARGETNAME from the previous
#  target may stick around.
TARGETNAME=
-include $(top_builddir)/src/lib/ldap/all.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= rlm_ldap
  TARGET	:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c groups.c user.c

SRC_CFLAGS	+= -I$(top_builddir)/src/modules/rlm_ldap
TGT_PREREQS	:= libfreeradius-ldap$(L)
LOG_ID_LIB	= 26
