TARGETNAME	:= libfreeradius-redis

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= redis.c crc16.c cluster.c

SRC_CFLAGS	:=
TGT_LDLIBS	:=  -lhiredis
