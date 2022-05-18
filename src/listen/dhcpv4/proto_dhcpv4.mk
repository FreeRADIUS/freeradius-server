TARGETNAME	:= proto_dhcpv4

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_dhcpv4.c

TGT_PREREQS	:= libfreeradius-dhcpv4$(L) libfreeradius-io$(L)
