TARGET := atomic_queue_test

SOURCES		:= atomic_queue_test.c

TGT_PREREQS	:= libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)

