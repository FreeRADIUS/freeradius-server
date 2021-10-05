TARGETNAME	:= proto_dns_udp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_dns_udp.c

TGT_PREREQS	:= libfreeradius-dns.a
