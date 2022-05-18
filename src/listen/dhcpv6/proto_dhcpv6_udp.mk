TARGETNAME	:= proto_dhcpv6_udp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_dhcpv6_udp.c

TGT_PREREQS	:= libfreeradius-dhcpv6$(L)
