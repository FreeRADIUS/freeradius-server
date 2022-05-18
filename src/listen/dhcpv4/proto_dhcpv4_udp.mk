TARGETNAME	:= proto_dhcpv4_udp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_dhcpv4_udp.c

TGT_PREREQS	:= libfreeradius-dhcpv4$(L) libfreeradius-arp$(L)
