TARGETNAME	:= process_dhcpv4

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= base.c

TGT_PREREQS	:= libfreeradius-dhcpv4$(L)
