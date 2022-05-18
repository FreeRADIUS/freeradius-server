#  This needs to be cleared explicitly, as the libfreeradius-json.mk
#  might not always be available, and the TARGETNAME from the previous
#  target may stick around.
TARGETNAME	:=
-include $(top_builddir)/src/lib/json/all.mk

ifneq "${TARGETNAME}" ""
  TARGETNAME	:= rlm_json
  TARGET        := $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c

#
#  Append SRC_CFLAGS and leave TGT_LDLIBS alone
#
SRC_CFLAGS	+= -I$(top_builddir)/src/lib/json/
TGT_PREREQS	:= libfreeradius-json$(L)
LOG_ID_LIB	= 24
