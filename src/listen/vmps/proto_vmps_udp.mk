TARGETNAME	:= proto_vmps_udp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_vmps_udp.c

TGT_PREREQS	:= libfreeradius-vmps.a
