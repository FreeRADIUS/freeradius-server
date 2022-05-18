TARGET 		:= message_set_test$(E)

SOURCES		:= message_set_test.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L)
TGT_LDLIBS	:= $(LIBS)

