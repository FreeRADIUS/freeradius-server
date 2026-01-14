#  Check to see if we have libfreeradius-curl, as that's a hard dependency
TARGETNAME	:=
-include $(top_builddir)/src/lib/curl/all.mk
TARGET		:=

ifneq "$(TARGETNAME)" ""
TARGETNAME	:= rlm_ftp
TARGET		:= $(TARGETNAME)$(L)
TGT_PREREQS	+= libfreeradius-curl$(L)
endif

SOURCES		:= $(TARGETNAME).c
LOG_ID_LIB	= 62
