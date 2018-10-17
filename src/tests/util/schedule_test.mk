TARGET := schedule_test

SOURCES		:= schedule_test.c

TGT_PREREQS	:= libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS)

