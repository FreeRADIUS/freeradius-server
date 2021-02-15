TARGETNAME	:= proto_detail

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_detail.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a libfreeradius-io.a
