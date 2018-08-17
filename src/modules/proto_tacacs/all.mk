TARGETNAME	:= proto_tacacs

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_tacacs.c

TGT_PREREQS	:= libfreeradius-tacacs.a
