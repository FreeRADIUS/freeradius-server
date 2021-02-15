TARGETNAME	:= proto_radius_udp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_radius_udp.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a
