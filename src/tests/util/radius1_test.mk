TARGET := radius1_test

SOURCES		:= radius1_test.c

TGT_PREREQS	:= libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)
