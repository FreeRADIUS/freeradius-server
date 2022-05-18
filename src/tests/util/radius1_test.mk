TARGET 		:= radius1_test$(E)

SOURCES		:= radius1_test.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L)
TGT_LDLIBS	:= $(LIBS)
