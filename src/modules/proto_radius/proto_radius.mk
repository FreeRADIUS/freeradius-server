TARGETNAME	:= proto_radius

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_radius.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a
