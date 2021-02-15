TARGETNAME	:= proto_radius_status

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_radius_status.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a

