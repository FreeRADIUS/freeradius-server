TARGETNAME	:= proto_dhcpv4_udp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_dhcpv4_udp.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-dhcpv4.a libfreeradius-arp.a
