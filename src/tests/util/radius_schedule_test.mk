TARGET := radius_schedule_test

SOURCES		:= radius_schedule_test.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-server.a libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)

