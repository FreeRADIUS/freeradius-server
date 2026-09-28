#  Check to see if we libfreeradius-curl, as that's a hard dependency
#  which in turn depends on json-c.
TARGETNAME	:=
-include $(top_builddir)/src/lib/curl/all.mk
TARGET		:=

ifneq "$(TARGETNAME)" ""
TARGETNAME	:= rlm_ocsp
TARGET		:= $(TARGETNAME)$(L)
TGT_PREREQS	+= libfreeradius-curl$(L)
endif
TGT_CATEGORY	:=

SOURCES		:= $(TARGETNAME).c
LOG_ID_LIB	= 68
