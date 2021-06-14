TARGETNAME	:= proto_control

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_control.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a libfreeradius-radius.a libfreeradius-io.a
