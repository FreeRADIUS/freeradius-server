TARGETNAME	:= proto_vmps_udp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_vmps_udp.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-vmps.a
