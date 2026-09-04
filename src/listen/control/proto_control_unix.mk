TARGETNAME	:= proto_control_unix

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= proto_control_unix.c

TGT_PREREQS	:= $(LIBFREERADIUS_UTIL) libfreeradius-control$(L) libfreeradius-bio$(L)
