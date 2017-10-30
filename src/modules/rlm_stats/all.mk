TARGETNAME	:= rlm_stats

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= rlm_stats.c
