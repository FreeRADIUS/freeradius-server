TARGET 		:= worker_test$(E)

SOURCES		:= worker_test.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L) libfreeradius-util$(L)
TGT_LDLIBS	:= $(LIBS)

