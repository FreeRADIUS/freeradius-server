TARGET 		:= atomic_ring_test$(E)

SOURCES		:= atomic_ring_test.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L)
TGT_LDLIBS	:= $(LIBS) $(PTHREADLIBS)
