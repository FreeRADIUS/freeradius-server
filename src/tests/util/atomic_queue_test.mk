TARGET 		:= atomic_queue_test$(E)

SOURCES		:= atomic_queue_test.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L)
TGT_LDLIBS	:= $(LIBS)

