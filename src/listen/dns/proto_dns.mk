TARGETNAME	:= proto_dns

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_dns.c

TGT_PREREQS	:= libfreeradius-dns$(L) libfreeradius-io$(L)
