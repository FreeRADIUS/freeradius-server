TARGETNAME	:= proto_detail_work

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_detail_work.c

TGT_PREREQS	:= libfreeradius-util$(L)
