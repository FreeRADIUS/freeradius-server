TARGETNAME	:= proto_cron_crontab

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_cron_crontab.c

TGT_PREREQS	:= libfreeradius-util$(L)
