TARGETNAME	:= proto_cron_crontab

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_cron_crontab.c

TGT_PREREQS	:= libfreeradius-util.a
