TARGET := ring_buffer_test

SOURCES		:= ring_buffer_test.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)

