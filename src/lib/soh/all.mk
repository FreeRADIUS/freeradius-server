TARGETNAME	:= libfreeradius-soh

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= soh.c
TGT_PREREQS	:= libfreeradius-util.la
