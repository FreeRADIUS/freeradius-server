TARGETNAME	:= proto_dhcpv6_process

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_dhcpv6_process.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-dhcpv6.a
