TARGETNAME	:= proto_radius_tcp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_radius_tcp.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a
