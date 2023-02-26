TARGETNAME	:= process_bfd

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= base.c

TGT_PREREQS	:= libfreeradius-util$(L)

