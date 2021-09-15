TARGETNAME	:= proto_cron

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_cron.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a
