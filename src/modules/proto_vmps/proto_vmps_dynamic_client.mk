TARGETNAME	:= proto_vmps_dynamic_client

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_vmps_dynamic_client.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-vqp.a
