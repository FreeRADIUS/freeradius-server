TARGETNAME	:= proto_bfd

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_bfd.c
