TARGET := radius_schedule_test

SOURCES		:= radius_schedule_test.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-server.a libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)

