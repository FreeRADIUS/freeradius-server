TARGET := atomic_queue_test

SOURCES		:= atomic_queue_test.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a libfreeradius-util.a
TGT_LDLIBS	:= $(LIBS)

