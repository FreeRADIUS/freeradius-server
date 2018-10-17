TARGET := ring_buffer_test

SOURCES		:= ring_buffer_test.c

TGT_PREREQS	:= libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)

