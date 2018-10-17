TARGET := radius_schedule_test

SOURCES		:= radius_schedule_test.c

TGT_PREREQS	:= libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)

