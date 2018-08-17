TARGET := radius1_test

SOURCES		:= radius1_test.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a libfreeradius-util.a
TGT_LDLIBS	:= $(LIBS)
