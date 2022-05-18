TARGETNAME	:= proto_tacacs_tcp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_tacacs_tcp.c

TGT_PREREQS	:= libfreeradius-tacacs$(L)
