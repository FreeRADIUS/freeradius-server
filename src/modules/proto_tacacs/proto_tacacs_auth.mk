TARGETNAME	:= proto_tacacs_auth

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_tacacs_auth.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-tacacs.a
