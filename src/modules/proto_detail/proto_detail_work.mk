TARGETNAME	:= proto_detail_work

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_detail_work.c

TGT_PREREQS	:= libfreeradius-util.a
