TARGETNAME	:= proto_detail_file

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_detail_file.c

TGT_PREREQS	:= libfreeradius-util.a
