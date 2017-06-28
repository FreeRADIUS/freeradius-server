TARGETNAME	:= proto_vmps

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_vmps.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-vqp.a libfreeradius-io.a
