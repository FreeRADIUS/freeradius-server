TARGETNAME	:= proto_radius_auth

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_radius_auth.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a

