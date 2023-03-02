TARGETNAME	:= proto_bfd_udp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c session.c

TGT_PREREQS	:= libfreeradius-bfd$(L)
