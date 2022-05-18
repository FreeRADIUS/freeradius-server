TARGETNAME	:= proto_detail_file

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_detail_file.c

TGT_PREREQS	:= libfreeradius-util$(L)
