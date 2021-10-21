TARGET := radius_schedule_test

SOURCES		:= radius_schedule_test.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)

