TARGETNAME	:= libfreeradius-json

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= json_missing.c json.c jpath.c
SRC_CFLAGS	:=
TGT_LDLIBS	:=  -ljson-c
