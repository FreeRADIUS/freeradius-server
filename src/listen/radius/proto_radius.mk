TARGETNAME	:= proto_radius

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_radius.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-radius$(L) libfreeradius-io$(L)
