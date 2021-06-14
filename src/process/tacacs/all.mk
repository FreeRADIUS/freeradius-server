TARGETNAME	:= process_tacacs

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= base.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-tacacs.a
