TARGETNAME	:= libfreeradius-kafka

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= base.c

SRC_CFLAGS	:=   
TGT_LDLIBS	:=  -lrdkafka 
