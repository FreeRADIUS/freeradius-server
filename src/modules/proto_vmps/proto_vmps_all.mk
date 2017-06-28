TARGETNAME	:= proto_vmps_all

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_vmps_all.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-vqp.a
