TARGETNAME	:= proto_radius_udp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_radius_udp.c

TGT_PREREQS	:= libfreeradius-radius$(L) proto_radius$(L)
