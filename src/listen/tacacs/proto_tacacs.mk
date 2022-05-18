TARGETNAME	:= proto_tacacs

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_tacacs.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-tacacs$(L) libfreeradius-io$(L)
