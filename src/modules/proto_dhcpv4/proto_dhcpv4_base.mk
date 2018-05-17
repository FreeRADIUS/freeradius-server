TARGETNAME	:= proto_dhcpv4_base

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_dhcpv4_base.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-dhcpv4.a
