TARGETNAME	:= libfreeradius-soh

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= soh.c
TGT_PREREQS	:= libfreeradius-util$(L)
