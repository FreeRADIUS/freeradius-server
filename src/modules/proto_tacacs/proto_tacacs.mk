TARGETNAME	:= proto_tacacs

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_tacacs.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a libfreeradius-tacacs.a libfreeradius-io.a
