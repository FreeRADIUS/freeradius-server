TARGET := radius1_test

SOURCES		:= radius1_test.c

TGT_PREREQS	:= libfreeradius-io.a libfreeradius-util.a libfreeradius-radius.a libfreeradius-server.a
TGT_LDLIBS	:= $(LIBS)
