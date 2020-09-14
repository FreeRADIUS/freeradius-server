TARGETNAME	:= proto_tftp_udp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES	:= proto_tftp_udp.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-tftp.a
