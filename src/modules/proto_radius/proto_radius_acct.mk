TARGETNAME	:= proto_radius_acct

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_radius_acct.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a

