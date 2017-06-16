TARGET := schedule_test

SOURCES		:= schedule_test.c

TGT_PREREQS	:= libfreeradius-io.a libfreeradius-util.a libfreeradius-server.a libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)

