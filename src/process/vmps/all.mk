TARGETNAME	:= process_vmps

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= base.c

TGT_PREREQS	:= libfreeradius-vmps.a
