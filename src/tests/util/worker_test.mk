TARGET := worker_test

SOURCES		:= worker_test.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-server.a libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)

