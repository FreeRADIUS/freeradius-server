TARGET := worker_test

SOURCES		:= worker_test.c

TGT_PREREQS	:= libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)

