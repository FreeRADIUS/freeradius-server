TARGETNAME	:= proto_tacacs_autz

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_tacacs_autz.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-tacacs.a
