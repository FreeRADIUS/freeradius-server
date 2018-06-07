TARGETNAME	:= proto_control_tcp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_control_tcp.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-control.a
