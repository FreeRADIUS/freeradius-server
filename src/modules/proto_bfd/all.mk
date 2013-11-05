TARGETNAME	:= proto_bfd

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= bfd.c
