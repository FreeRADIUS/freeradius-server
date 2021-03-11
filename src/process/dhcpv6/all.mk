TARGETNAME	:= process_dhcpv6

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= base.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-dhcpv6.a
