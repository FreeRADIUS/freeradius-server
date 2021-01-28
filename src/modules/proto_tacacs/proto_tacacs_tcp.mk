TARGETNAME	:= proto_tacacs_tcp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_tacacs_tcp.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-tacacs.a
