TARGET := control_test

SOURCES		:= control_test.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)

