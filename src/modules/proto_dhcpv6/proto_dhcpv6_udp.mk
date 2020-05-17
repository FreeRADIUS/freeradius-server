TARGETNAME	:= proto_dhcpv6_udp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_dhcpv6_udp.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-dhcpv6.a
