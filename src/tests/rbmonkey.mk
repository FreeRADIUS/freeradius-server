TARGET := rbmonkey

SOURCES := rbmonkey.c

TGT_PREREQS	:= libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
TGT_INSTALLDIR	:=
