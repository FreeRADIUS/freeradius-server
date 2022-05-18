TARGET 		:= ring_buffer_test$(E)

SOURCES		:= ring_buffer_test.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L)
TGT_LDLIBS	:= $(LIBS)

