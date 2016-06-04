TARGETNAME	:= proto_dhcp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_dhcp.c

TGT_PREREQS	:= libfreeradius-dhcp.a
