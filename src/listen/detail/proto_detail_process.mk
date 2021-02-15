TARGETNAME	:= proto_detail_process

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_detail_process.c

TGT_PREREQS	:= libfreeradius-util.a
