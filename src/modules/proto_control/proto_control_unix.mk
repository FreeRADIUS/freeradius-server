TARGETNAME	:= proto_control_unix

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_control_unix.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-control.a
