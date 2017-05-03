TARGET := message_set_test

SOURCES		:= message_set_test.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-server.a libfreeradius-radius.a libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)

