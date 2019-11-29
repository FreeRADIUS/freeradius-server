TARGETNAME	:= proto_radius_load

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_radius_load.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a
