TARGETNAME	:= proto_tftp_process

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_tftp_process.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-tftp.a
