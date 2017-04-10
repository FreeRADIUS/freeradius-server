TARGET := schedule_test

SOURCES		:= schedule_test.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-server.a libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)

