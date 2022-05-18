TARGETNAME	:= proto_detail

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_detail.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L)
