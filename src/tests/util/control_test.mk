TARGET 		:= control_test$(E)

SOURCES		:= control_test.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L)
TGT_LDLIBS	:= $(LIBS)

