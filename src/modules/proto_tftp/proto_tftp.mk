TARGETNAME	:= proto_tftp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_tftp.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a libfreeradius-radius.a libfreeradius-tftp.a libfreeradius-io.a
