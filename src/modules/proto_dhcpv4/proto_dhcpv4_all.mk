TARGETNAME	:= proto_dhcpv4_all

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_dhcpv4_all.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-dhcpv4.a
