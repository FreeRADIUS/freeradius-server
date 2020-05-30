TARGETNAME	:= proto_dhcpv6

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_dhcpv6.c

TGT_PREREQS	:= libfreeradius-dhcpv6.a libfreeradius-util.a libfreeradius-io.a
