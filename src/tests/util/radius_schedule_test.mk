TARGET 		:= radius_schedule_test$(E)

SOURCES		:= radius_schedule_test.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L)
TGT_LDLIBS	:= $(LIBS)

