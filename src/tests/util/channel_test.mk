TARGET := channel_test

SOURCES		:= channel_test.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-server.a libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)

