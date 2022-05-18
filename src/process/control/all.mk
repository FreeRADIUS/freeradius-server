TARGETNAME	:= process_control

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= base.c

TGT_PREREQS	:= libfreeradius-util$(L)
