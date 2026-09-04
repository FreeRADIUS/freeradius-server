TARGETNAME	:= proto_load_step

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_load_step.c

TGT_PREREQS	:= $(LIBFREERADIUS_UTIL)
