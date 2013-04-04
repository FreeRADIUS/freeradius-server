TARGETNAME	:= proto_dhcp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= dhcp.c
