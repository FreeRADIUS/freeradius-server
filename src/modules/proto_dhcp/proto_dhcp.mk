TARGETNAME	:= proto_dhcp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= dhcpd.c

TGT_PREREQS	:= libfreeradius-dhcp.a
