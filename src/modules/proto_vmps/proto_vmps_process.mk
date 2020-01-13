TARGETNAME	:= proto_vmps_process

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_vmps_process.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-vqp.a
