TARGETNAME	:= proto_vmps

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_vmps.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-vmps$(L) libfreeradius-io$(L)
