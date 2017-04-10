TARGET := ring_buffer_test

SOURCES		:= ring_buffer_test.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-server.a libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)

