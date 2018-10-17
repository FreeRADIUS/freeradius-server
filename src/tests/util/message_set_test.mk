TARGET := message_set_test

SOURCES		:= message_set_test.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a libfreeradius-util.a
TGT_LDLIBS	:= $(LIBS)

