TARGETNAME	:= proto_cron

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_cron.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L)
