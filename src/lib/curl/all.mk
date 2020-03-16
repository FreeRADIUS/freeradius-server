TARGETNAME	:= libfreeradius-curl

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= base.c io.c

SRC_CFLAGS	:= 
TGT_LDLIBS	:= -lcurl

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a
