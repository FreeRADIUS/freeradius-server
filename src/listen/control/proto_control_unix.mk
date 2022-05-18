TARGETNAME	:= proto_control_unix

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_control_unix.c

TGT_PREREQS	:= libfreeradius-control$(L)
