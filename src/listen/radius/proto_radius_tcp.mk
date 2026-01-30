TARGETNAME	:= proto_radius_tcp

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_radius_tcp.c

TGT_PREREQS	:= libfreeradius-radius$(L) proto_radius$(L)
