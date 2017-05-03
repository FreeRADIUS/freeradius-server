TARGETNAME	:= proto_radius_coa

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_radius_coa.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a

