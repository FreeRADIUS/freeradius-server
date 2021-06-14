TARGETNAME	:= proto_dhcpv4

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_dhcpv4.c

TGT_PREREQS	:= libfreeradius-dhcpv4.a libfreeradius-util.a libfreeradius-io.a
