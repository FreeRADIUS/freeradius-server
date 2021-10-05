TARGETNAME	:= proto_dns

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_dns.c

TGT_PREREQS	:= libfreeradius-dns.a libfreeradius-io.a
