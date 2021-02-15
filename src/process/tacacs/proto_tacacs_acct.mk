TARGETNAME	:= proto_tacacs_acct

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_tacacs_acct.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-tacacs.a
