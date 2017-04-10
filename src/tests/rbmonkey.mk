TARGET := rbmonkey

SOURCES := rbmonkey.c

TGT_PREREQS	:= libfreeradius-util.a
TGT_LDLIBS	:= $(LIBS)
TGT_INSTALLDIR	:=
