TARGET := radius_schedule_test

SOURCES		:= radius_schedule_test.c

TGT_PREREQS	:= libfreeradius-io.a libfreeradius-util.a libfreeradius-radius.a libfreeradius-server.a
TGT_LDLIBS	:= $(LIBS)

