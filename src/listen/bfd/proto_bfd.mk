TARGETNAME	:= proto_bfd

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L)  libfreeradius-internal$(L) libfreeradius-bfd$(L)
