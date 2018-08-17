TARGETNAME	:= rlm_stats

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= rlm_stats.c

TGT_PREREQS	:= libfreeradius-radius.a libfreeradius-util.a
