TARGET := ipaddr_test

SOURCES := ipaddr_test.c

TGT_PREREQS	:= libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
TGT_INSTALLDIR	:=
