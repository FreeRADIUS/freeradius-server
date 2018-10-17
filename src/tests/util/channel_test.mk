TARGET := channel_test

SOURCES		:= channel_test.c

TGT_PREREQS	:= libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)

