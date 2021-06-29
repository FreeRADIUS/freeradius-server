TARGETNAME	:= proto_load_step

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_load_step.c

TGT_PREREQS	:= libfreeradius-util.a
