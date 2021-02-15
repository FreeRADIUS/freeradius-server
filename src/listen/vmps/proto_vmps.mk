TARGETNAME	:= proto_vmps

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_vmps.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a libfreeradius-radius.a libfreeradius-vmps.a libfreeradius-io.a
