TARGETNAME	:= proto_vmps

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= proto_vmps.c vqp.c

