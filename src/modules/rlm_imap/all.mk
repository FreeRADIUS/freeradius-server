#  Check to see if we libfreeradius-curl, as that's a hard dependency
#  which in turn depends on json-c.
TARGETNAME	:=
-include $(top_builddir)/src/lib/curl/all.mk
TARGET		:=

ifneq "$(TARGETNAME)" ""
TARGET		:= rlm_imap$(L)
TGT_PREREQS	+= libfreeradius-curl$(L)
endif

SOURCES		:= rlm_imap.c
LOG_ID_LIB	= 22
