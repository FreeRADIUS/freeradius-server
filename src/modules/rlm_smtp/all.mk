#  Check to see if we libfreeradius-curl, as that's a hard dependency
#  which in turn depends on json-c.
TARGETNAME	:=
-include $(top_builddir)/src/lib/curl/all.mk
TARGET		:=

ifneq "$(TARGETNAME)" ""
TARGET		:= rlm_smtp.a
TGT_PREREQS	+= libfreeradius-curl.a
endif

SOURCES		:= rlm_smtp.c
