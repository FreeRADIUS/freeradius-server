TARGETNAME	:= proto_load

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_load.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a
