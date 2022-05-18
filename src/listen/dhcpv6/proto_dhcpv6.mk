TARGETNAME	:= proto_dhcpv6

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_dhcpv6.c

TGT_PREREQS	:= libfreeradius-dhcpv6$(L) libfreeradius-io$(L)
